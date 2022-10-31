#include "protocol.h"
#include <WinSock2.h>
#include <any>
#include <vector>

//

template<typename T>
void parse_application(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    headers.push_back(std::vector<uint8_t>{begin, end});
}

template<>
inline void parse_application<dns_packet>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto dns = *(dns_packet*)begin;
    dns.id = ntohs(dns.id);

    uint16_t tmp = *(uint16_t*)&dns.flags;
    tmp = ntohs(tmp);
    dns.flags = *(dns_packet::flag_t*)&tmp;

    dns.questions = ntohs(dns.questions);
    dns.answer_rrs = ntohs(dns.answer_rrs);
    dns.authority_rrs = ntohs(dns.authority_rrs);
    dns.additional_rrs = ntohs(dns.additional_rrs);

    std::vector<uint8_t> buf{(uint8_t*)(&dns), (uint8_t*)(&dns + 1)};
    buf.insert(buf.end(), begin + sizeof(dns), end);
    headers.push_back(std::move(buf));
}

template<typename T>
void parse_transport(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    headers.push_back(std::vector<uint8_t>{begin, end});
}

template<>
inline void parse_transport<tcp_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto tcp = *(tcp_header*)begin;
    tcp.src = ntohs(tcp.src);
    tcp.dst = ntohs(tcp.dst);
    tcp.seq = ntohl(tcp.seq);
    tcp.ack = ntohl(tcp.ack);
    tcp.window_size = ntohs(tcp.window_size);
    tcp.checksum = ntohs(tcp.checksum);
    tcp.urgent_ptr = ntohs(tcp.urgent_ptr);

    headers.push_back(tcp);
    // begin += tcp.len

    switch (tcp.type()) {
        case 53:
            return parse_application<dns_packet>(begin, end, headers);
        default:
            return parse_application<void>(begin, end, headers);
    }
}

template<>
inline void parse_transport<udp_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto udp = *(udp_header*)begin;
    udp.src = ntohs(udp.src);
    udp.dst = ntohs(udp.dst);
    udp.len = ntohs(udp.len);
    udp.checksum = ntohs(udp.checksum);

    headers.push_back(udp);
    begin += sizeof(udp);
    switch (udp.type()) {
        case 53:
            return parse_application<dns_packet>(begin, end, headers);
        default:
            return parse_application<void>(begin, end, headers);
    }
}

template<>
inline void parse_transport<icmp_packet>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto icmp = *(icmp_packet*)begin;
    icmp.checksum = ntohs(icmp.checksum);
    icmp.field = ntohl(icmp.field);

    std::vector<uint8_t> buf{(uint8_t*)(&icmp), (uint8_t*)(&icmp + 1)};
    buf.insert(buf.end(), begin + sizeof(icmp), end);
    headers.push_back(std::move(buf));
}

template<typename T>
void parse_network(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    headers.push_back(std::vector<uint8_t>{begin, end});
}

template<>
inline void parse_network<ipv6_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto ip6 = *(ipv6_header*)begin;

    uint32_t tmp = *(uint32_t*)&ip6;
    tmp = ntohl(tmp);
    ip6.version = (tmp & (0xfu << 28)) >> 28;
    ip6.traffic_class = (tmp & (0xff << 20)) >> 20;
    ip6.flow_label = tmp;

    ip6.payload_len = ntohs(ip6.payload_len);
    headers.push_back(ip6);
    begin += sizeof(ip6); //这里没错，ipv6不是变长的
    switch (ip6.next_header) {
        case ipv6_header::TCP:
            return parse_transport<tcp_header>(begin, end, headers);
        case ipv6_header::UDP:
            return parse_transport<udp_header>(begin, end, headers);
        case ipv6_header::IPv6:
            return parse_network<ipv6_header>(begin, end, headers);
        default:
            return parse_transport<void>(begin, end, headers);
    }
}

template<>
inline void parse_network<ipv4_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto ip = *(ipv4_header*)begin;
    ip.len = ntohs(ip.len);
    ip.id = ntohs(ip.id);

    uint16_t tmp = *(&ip.id + 1);
    tmp = ntohs(tmp);
    ip.df = (tmp & (1 << 14)) >> 14;
    ip.mf = (tmp & (1 << 13)) >> 13;
    ip.offset = tmp;

    ip.checksum = ntohs(ip.checksum);

    std::vector<uint8_t> buf{(uint8_t*)(&ip), (uint8_t*)(&ip + 1)};
    buf.insert(buf.end(), begin + sizeof(ip), begin + ip.header_len * 4);
    headers.push_back(std::move(buf));

    begin += ip.header_len * 4;

    switch (ip.proto) {
        case ipv4_header::ICMP:
            return parse_transport<icmp_packet>(begin, end, headers);
        case ipv4_header::IPv4:
            return parse_network<ipv4_header>(begin, end, headers);
        case ipv4_header::TCP:
            return parse_transport<tcp_header>(begin, end, headers);
        case ipv4_header::UDP:
            return parse_transport<udp_header>(begin, end, headers);
        case ipv4_header::IPv6:
            return parse_network<ipv6_header>(begin, end, headers);
        default:
            return parse_transport<void>(begin, end, headers);
    }
}

template<>
inline void parse_network<arp_packet>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    auto arp = *(arp_packet*)begin;
    arp.hardware_type = ntohs(arp.hardware_type);
    arp.proto_type = ntohs(arp.proto_type);
    arp.op = ntohs(arp.op);
    headers.push_back(arp);
    begin += sizeof(arp);
}

inline void parse_datalink(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    eth_header eth = *(eth_header*)begin;
    eth.len = ntohs(eth.len);
    if (eth.len <= 0x0600) {
        headers.push_back(std::vector<uint8_t>{begin, end});
        return; //不支持携带LLC层的mac帧
    }
    headers.push_back(eth);
    begin += sizeof(eth);
    switch (eth.type) {
        case eth_header::IPv4:
            return parse_network<ipv4_header>(begin, end, headers);
        case eth_header::ARP:
            return parse_network<arp_packet>(begin, end, headers);
        case eth_header::IPv6:
            return parse_network<ipv6_header>(begin, end, headers);
        default:
            return parse_network<void>(begin, end, headers);
    }
}
