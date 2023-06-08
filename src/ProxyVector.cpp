#include "ProxyVector.h"
#include <QDataStream>
//
using namespace std::chrono_literals;
static constexpr size_t LENGTH = 7301;
static constexpr std::chrono::seconds INTERVAL = 5s;

//
ProxyVector::ProxyVector()
    : sz(0), db(QSqlDatabase::addDatabase("QSQLITE")), cacheOffset(0) {
    db.setDatabaseName("db");
    sql_assert(db.open());
    // 将数据移交给操作系统后就润，异步
    exec("PRAGMA synchronous = OFF");
    // 取消日志
    exec("PRAGMA journal_mode = OFF");
    exec("DROP TABLE IF EXISTS packets");

    exec("CREATE TABLE packets ("
         "  data BLOB NOT NULL"
         ")");
}

// 是否需要/可以存档：数量过多 且 cd冷却时间结束
bool ProxyVector::is_activate() const {
    if (blobCache.size() < LENGTH)
        return false;
    if (std::chrono::steady_clock::now() < lastTime + INTERVAL)
        return false;
    return true;
}

void ProxyVector::archive() {
    bool e = true;
    exec("BEGIN");
    QSqlQuery query;
    e &= query.prepare("INSERT INTO packets VALUES(?)");
    for (auto& blob: blobCache) {
        query.addBindValue(blob);
        e &= query.exec();
        query.finish();
    }
    exec("COMMIT");
    sql_assert(e);

    packets.clear();
    blobCache.clear();
    lastTime = std::chrono::steady_clock::now();
}

void ProxyVector::push_back(pack&& pkt) {
    if (is_activate()) {
        archive();
    }
    ++sz;
    QByteArray buf;
    QDataStream ds{&buf, QIODevice::WriteOnly};
    ds << pkt;
    blobCache.push_back(std::move(buf));
    packets.push_back(std::move(pkt));
}

const pack& ProxyVector::operator[](size_t i) {
    [[unlikely]] if (i < 0 || sz <= i)
        throw std::out_of_range("invalid visit to ProxyVector");

    size_t writeOffset = sz - packets.size();
    if (writeOffset <= i) {
        return packets[i - writeOffset];
    }

    // readCache需要换页
    if (i < cacheOffset || cacheOffset + readCache.size() <= i) {
        readCache.clear();

        cacheOffset = i / LENGTH * LENGTH;
        size_t cacheEnd = std::min(sz, cacheOffset + LENGTH);

        // 必须要读，因为不在写缓存里
        QSqlQuery query;
        sql_assert(query.exec(QString::asprintf(
            "SELECT data FROM packets WHERE rowid BETWEEN %zu AND %zu",
            cacheOffset + 1, std::min(writeOffset, cacheEnd))));
        while (query.next()) {
            auto buf = query.value(0).toByteArray();
            QDataStream ds(buf); // 只读
            pack pk;
            ds >> pk;
            readCache.push_back(std::move(pk));
        }
        // 先不把写缓存复制到读缓存了吧
    }
    return readCache[i - cacheOffset];
}

void ProxyVector::clear() {
    exec("DELETE FROM packets");
    readCache.clear();
    packets.clear();
    cacheOffset = 0;
    sz = 0;
}
