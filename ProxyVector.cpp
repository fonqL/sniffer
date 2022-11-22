#include "ProxyVector.h"
#include "protocol.h"
#include <QDataStream>
//
using namespace std::chrono_literals;
static constexpr size_t LENGTH = 8000;
static constexpr std::chrono::seconds INTERVAL = 5s;

using vec8_t = std::vector<uint8_t>;

enum type_enum : uint8_t {
    TYPE_eth_header,
    TYPE_arp_packet,
    TYPE_ipv4_header,
    TYPE_ipv6_header,
    TYPE_icmp_packet,
    TYPE_tcp_header,
    TYPE_udp_header,
    TYPE_dns_packet,
    TYPE_vec8_t
};

template<typename T>
static constexpr uint8_t T_E = 99;

#define REG(T) \
    template<> \
    const uint8_t T_E<T> = TYPE_##T;

REG(eth_header)
REG(arp_packet)
REG(ipv4_header)
REG(ipv6_header)
REG(icmp_packet)
REG(tcp_header)
REG(udp_header)
REG(dns_packet)
REG(vec8_t)

#undef REG

//

QDataStream& operator<<(QDataStream& ds, const simple_info& x) {
    return ds << x.t << x.raw_data;
}
QDataStream& operator>>(QDataStream& ds, simple_info& x) {
    return ds >> x.t >> x.raw_data;
}

QDataStream& operator<<(QDataStream& ds, const vec8_t& x) {
    auto arr = QByteArray::fromRawData((const char*)(x.data()), x.size());
    return ds << arr;
}
QDataStream& operator>>(QDataStream& ds, vec8_t& x) {
    QByteArray arr;
    ds >> arr;
    x.insert(x.end(), (const uint8_t*)(arr.begin()), (const uint8_t*)(arr.end()));
    return ds;
}
//

#define MACRO(T)                                           \
    QDataStream& operator<<(QDataStream& ds, const T& x) { \
        QByteArray arr((const char*)(&x), sizeof(x));      \
        return ds << arr;                                  \
    }                                                      \
    QDataStream& operator>>(QDataStream& ds, T& x) {       \
        QByteArray arr;                                    \
        ds >> arr;                                         \
        x = *(T*)arr.data();                               \
        return ds;                                         \
    }

#define MACRO2(ST, BT)                                                      \
    QDataStream& operator<<(QDataStream& ds, const ST& x) {                 \
        auto& bx = (const BT&)(x);                                          \
        auto arr = QByteArray::fromRawData((const char*)(&bx), sizeof(bx)); \
        return ds << arr << x.data;                                         \
    }                                                                       \
    QDataStream& operator>>(QDataStream& ds, ST& x) {                       \
        QByteArray arr;                                                     \
        ds >> arr >> x.data;                                                \
        (BT&)x = *(BT*)(arr.data());                                        \
        return ds;                                                          \
    }

MACRO(eth_header)
MACRO(arp_packet)
MACRO(ipv4_header)
MACRO(ipv6_header)
MACRO(tcp_header)
MACRO(udp_header)

MACRO2(icmp_packet, icmp_packet_base)
MACRO2(dns_packet, dns_packet_base)

#undef MACRO
#undef MACRO2
//

template<typename T>
bool check(QDataStream& ds, const std::any& x) {
    if (x.type() == typeid(T)) {
        ds << T_E<T> << std::any_cast<const T&>(x);
        return true;
    }
    return false;
}
template<typename... Ts>
void match(QDataStream& ds, const std::any& x) {
    bool e = (check<Ts>(ds, x) || ...);
    if (!e) throw std::runtime_error{"serialise error"};
}

QDataStream& operator<<(QDataStream& ds, const std::vector<std::any>& x) {
    ds << x.size();
    bool zero = true;
    for (auto& item: x) {
        if (zero) {
            ds << std::any_cast<const simple_info&>(item);
            zero = false;
            continue;
        }
        match<eth_header,
              arp_packet,
              ipv4_header,
              ipv6_header,
              icmp_packet,
              tcp_header,
              udp_header,
              dns_packet,
              vec8_t>(ds, item);
    }
    return ds;
}
//

template<typename T>
bool check(QDataStream& ds, type_enum id, std::vector<std::any>& vec) {
    if (id == T_E<T>) {
        std::any a = std::make_any<T>();
        auto& x = std::any_cast<T&>(a);
        ds >> x;
        vec.push_back(std::move(a));
        return true;
    }
    return false;
}

template<typename... Ts>
void match(QDataStream& ds, type_enum id, std::vector<std::any>& vec) {
    bool e = (check<Ts>(ds, id, vec) || ...);
    if (!e) throw std::runtime_error{"deserialise error"};
}

QDataStream& operator>>(QDataStream& ds, std::vector<std::any>& x) {
    size_t sz;
    ds >> sz;

    std::any a = std::make_any<simple_info>();
    auto& info = std::any_cast<simple_info&>(a);
    ds >> info;
    x.push_back(std::move(a));
    --sz;

    while (sz-- > 0) {
        type_enum id;
        ds >> id;
        match<eth_header,
              arp_packet,
              ipv4_header,
              ipv6_header,
              icmp_packet,
              tcp_header,
              udp_header,
              dns_packet,
              vec8_t>(ds, id, x);
    }
    return ds;
}

//
ProxyVector::ProxyVector()
    : offset(0), sz(0), db(QSqlDatabase::addDatabase("QSQLITE")) {
    db.setDatabaseName("db");
    sql_assert(db.open());
    exec("PRAGMA synchronous = OFF");
    exec("PRAGMA journal_mode = OFF");
    exec("DROP TABLE IF EXISTS packets");
    exec("CREATE TABLE packets ("
         "  data BLOB NOT NULL"
         ")");
}

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

void ProxyVector::push_back(std::vector<std::any>&& pkt) {
    // if (uint64_t(packets.size()) >= LENGTH && !blobCache.empty()) {
    if (is_activate()) {
        archive();
    }
    ++sz;
    QByteArray buf;
    QDataStream ds{&buf, QIODevice::WriteOnly};
    ds << pkt;
    blobCache.push_back(buf);
    packets.push_back(std::move(pkt));
}

const std::vector<std::any>&
ProxyVector::operator[](size_t i) {
    if (i < 0 || sz <= i) throw std::runtime_error("invalid vector subscript: out of bound");
    if (i < offset || offset + packets.size() <= i) {
        if (!blobCache.empty())
            archive();
        packets.clear();
        offset = i / LENGTH * LENGTH;
        QSqlQuery query;
        sql_assert(query.exec(QString::asprintf(
            "SELECT data FROM packets LIMIT %zu OFFSET %zu",
            LENGTH, offset)));
        while (query.next()) {
            std::vector<std::any> pkt;
            auto buf = query.value(0).toByteArray();
            QDataStream ds(&buf, QIODevice::ReadOnly);
            ds >> pkt;
            packets.push_back(std::move(pkt));
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
