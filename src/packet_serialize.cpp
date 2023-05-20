#include "packet.h"
//

QDataStream& operator<<(QDataStream& ds, const std::vector<uint8_t>& x) {
    return ds.writeBytes(
        reinterpret_cast<const char*>(x.data()),
        static_cast<uint>(x.size()));
}
QDataStream& operator>>(QDataStream& ds, std::vector<uint8_t>& x) {
    char* data;
    uint len;
    ds.readBytes(data, len);
    x.insert(x.end(),
             reinterpret_cast<const uint8_t*>(data),
             reinterpret_cast<const uint8_t*>(data + len));
    delete[] data;
    return ds;
}

//

QDataStream& operator<<(QDataStream& ds, const packet& pkt) {
    ds << static_cast<uint64_t>(pkt.mid - pkt.l_end);
    ds.writeBytes(
        reinterpret_cast<const char*>(pkt.l_end),
        static_cast<uint64_t>(pkt.r_end - pkt.l_end));
    return ds;
}
QDataStream& operator>>(QDataStream& ds, packet& pkt) {
    uint64_t lsize;
    char* data;
    uint len;

    ds >> lsize;
    ds.readBytes(data, len);

    pkt.impl.allocate(len);
    memcpy(pkt.impl.begin, data, len);
    pkt.l_end = pkt.impl.begin;
    pkt.r_end = pkt.impl.end;
    pkt.mid = pkt.l_end + lsize;

    delete[] data;
    return ds;
}

//

QDataStream& operator<<(QDataStream& ds, const pack& pk) {
    return ds << pk.time << pk.raw << pk.parsed;
}

QDataStream& operator>>(QDataStream& ds, pack& pk) {
    return ds >> pk.time >> pk.raw >> pk.parsed;
}
