#include "ProxyVector.h"
#include <QDataStream>
//
using namespace std::chrono_literals;
static constexpr size_t LENGTH = 8000;
static constexpr std::chrono::seconds INTERVAL = 5s;

//
ProxyVector::ProxyVector()
    : offset(0), sz(0), db(QSqlDatabase::addDatabase("QSQLITE")) {
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

    offset += packets.size();
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

    // 需要换页
    if (i < offset || offset + packets.size() <= i) {
        // 如果有未存档的缓存，则先存档
        if (!blobCache.empty())
            archive();
        else
            packets.clear();

        // packets和blobCache肯定都为空

        // 以i为中心，取出前后 LENGTH 个记录
        offset = i - LENGTH / 2;
        QSqlQuery query;
        sql_assert(query.exec(QString::asprintf(
            "SELECT data FROM packets WHERE rowid BETWEEN %zu AND %zu",
            offset, offset + LENGTH / 2)));
        while (query.next()) {
            pack pk;
            auto buf = query.value(0).toByteArray();
            // 只读
            QDataStream ds(buf);
            ds >> pk;
            packets.push_back(std::move(pk));
        }
    }
    return packets[i - offset];
}

void ProxyVector::clear() {
    exec("DELETE FROM packets");
    packets.clear();
    offset = 0;
    sz = 0;
}
