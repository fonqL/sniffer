#include "packet.h"
//

QDataStream& operator<<(QDataStream& ds, const std::vector<uint8_t>& x) {
    return ds.writeBytes(
        reinterpret_cast<const char*>(x.data()), // 合理的重解释，这其实被类型别名规则良定义
        static_cast<uint>(x.size()));
}
QDataStream& operator>>(QDataStream& ds, std::vector<uint8_t>& x) {
    char* data;
    uint len;
    ds.readBytes(data, len);
    x.insert(x.end(),
             reinterpret_cast<uint8_t*>(data),
             reinterpret_cast<uint8_t*>(data + len));
    delete[] data;
    return ds;
}

//

//
QDataStream& operator<<(QDataStream& ds, const blob& x) {
    return ds << static_cast<const std::vector<uint8_t>&>(x);
}
QDataStream& operator>>(QDataStream& ds, blob& x) {
    return ds >> static_cast<std::vector<uint8_t>&>(x);
}

template<class T>
    requires(std::is_trivial_v<T> && alignof(T) < 8) // 基于bit的定长协议头
QDataStream& operator<<(QDataStream& ds, const T& x) {
    auto sz = ds.writeRawData(reinterpret_cast<const char*>(&x), sizeof(T));
    assert(sz == sizeof(T));
    return ds;
}
template<class T>
    requires(std::is_trivial_v<T> && alignof(T) < 8)
QDataStream& operator>>(QDataStream& ds, T& x) {
    auto sz = ds.readRawData(reinterpret_cast<char*>(&x), sizeof(T));
    assert(sz == sizeof(T));
    return ds;
}

QDataStream& operator<<(QDataStream& ds, const icmp_packet& x) {
    return ds << static_cast<const icmp_packet_base&>(x)
              << x.data;
}
QDataStream& operator>>(QDataStream& ds, icmp_packet& x) {
    return ds >> static_cast<icmp_packet_base&>(x)
           >> x.data;
}

QDataStream& operator<<(QDataStream& ds, const dns_packet& x) {
    return ds << static_cast<const dns_packet_base&>(x)
              << x.data;
}
QDataStream& operator>>(QDataStream& ds, dns_packet& x) {
    return ds >> static_cast<dns_packet_base&>(x)
           >> x.data;
}

QDataStream& operator<<(QDataStream& ds, const packet& pkt) {
    ds << pkt.size();
    pkt.traverse([&ds]<typename T>(const T& proto) {
        ds << typeid(T).hash_code()
           << proto;
    });
    return ds;
}

template<class T>
bool input_case(size_t code, QDataStream& ds, llvm_vecsmall::SmallVector<std::any, 4>& layers) {
    if (code == typeid(T).hash_code()) {
        T proto;
        ds >> proto;
        layers.push_back(std::move(proto));
        return true;
    }
    return false;
}

template<class... Ts>
void input_match(size_t code, QDataStream& ds, llvm_vecsmall::SmallVector<std::any, 4>& layers, type_list<Ts...>) {
    bool res = (input_case<Ts>(code, ds, layers) || ...);
    if (!res) throw std::runtime_error{"deserialise error"};
}

QDataStream& operator>>(QDataStream& ds, packet& pkt) {
    size_t sz;
    ds >> sz;
    pkt.layers.reserve(sz);
    while (sz--) {
        size_t type_code;
        ds >> type_code;
        input_match(type_code, ds, pkt.layers, ValidProtos{});
    }
    return ds;
}

//

QDataStream& operator<<(QDataStream& ds, const pack& pk) {
    return ds << pk.time << pk.raw << pk.parsed;
}

QDataStream& operator>>(QDataStream& ds, pack& pk) {
    return ds >> pk.time >> pk.raw >> pk.parsed;
}
