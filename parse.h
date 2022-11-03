#include "protocol.h"
#include <WinSock2.h>
#include <any>

//
inline void parse_unknown(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    headers.push_back(std::vector<uint8_t>{begin, end});
}

template<typename T>
void parse_application(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) = delete;

template<>
inline void parse_application<dns_packet>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = std::make_any<dns_packet>();
    auto& dns = std::any_cast<dns_packet&>(a);
    *(dns_packet_base*)&dns = *(dns_packet_base*)begin;
    dns.id = ntohs(dns.id);

    uint16_t tmp = *(uint16_t*)&dns.flags;
    tmp = ntohs(tmp);
    dns.flags = *(dns_packet::flag_t*)&tmp;

    dns.questions = ntohs(dns.questions);
    dns.answer_rrs = ntohs(dns.answer_rrs);
    dns.authority_rrs = ntohs(dns.authority_rrs);
    dns.additional_rrs = ntohs(dns.additional_rrs);

    dns.data.insert(dns.data.end(), begin + sizeof(dns_packet_base), end);
    headers.push_back(std::move(a));
}

template<typename T>
void parse_transport(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) = delete;

template<>
inline void parse_transport<tcp_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = std::make_any<tcp_header>();
    auto& tcp = std::any_cast<tcp_header&>(a);
    *(tcp_header_base*)&tcp = *(tcp_header_base*)begin;
    tcp.src = ntohs(tcp.src);
    tcp.dst = ntohs(tcp.dst);
    tcp.seq = ntohl(tcp.seq);
    tcp.ack = ntohl(tcp.ack);
    tcp.window_size = ntohs(tcp.window_size);
    tcp.checksum = ntohs(tcp.checksum);
    tcp.urgent_ptr = ntohs(tcp.urgent_ptr);
    std::copy(begin + sizeof(tcp_header_base), begin + tcp.header_len * 4, tcp.op);

    begin += tcp.header_len * 4;
    auto tcp_type = tcp.type();
    headers.push_back(std::move(a));
    switch (tcp_type) {
        case 53:
            return parse_application<dns_packet>(begin, end, headers);
        default:
            return parse_unknown(begin, end, headers);
    }
}

template<>
inline void parse_transport<udp_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = *(udp_header*)begin;
    auto& udp = std::any_cast<udp_header&>(a);
    udp.src = ntohs(udp.src);
    udp.dst = ntohs(udp.dst);
    udp.len = ntohs(udp.len);
    udp.checksum = ntohs(udp.checksum);

    begin += sizeof(udp);
    auto udp_type = udp.type();
    headers.push_back(udp);
    switch (udp_type) {
        case 53:
            return parse_application<dns_packet>(begin, end, headers);
        default:
            return parse_unknown(begin, end, headers);
    }
}

template<>
inline void parse_transport<icmp_packet>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = std::make_any<icmp_packet>();
    auto& icmp = std::any_cast<icmp_packet&>(a);
    *(icmp_packet_base*)&icmp = *(icmp_packet_base*)begin;
    icmp.checksum = ntohs(icmp.checksum);
    icmp.field = ntohl(icmp.field);
    icmp.data.insert(icmp.data.end(), begin + sizeof(icmp_packet_base), end);

    headers.push_back(std::move(a));
}

template<typename T>
void parse_network(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) = delete;

template<>
inline void parse_network<ipv6_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = *(ipv6_header*)begin;
    auto& ip6 = std::any_cast<ipv6_header&>(a);

    uint32_t tmp = *(uint32_t*)&ip6;
    tmp = ntohl(tmp);
    ip6.version = (tmp & (0xfu << 28)) >> 28;
    ip6.traffic_class = (tmp & (0xff << 20)) >> 20;
    ip6.flow_label = tmp;

    ip6.payload_len = ntohs(ip6.payload_len);
    begin += sizeof(ip6); //这里没错，ipv6不是变长的
    auto ip6_next_header = ip6.next_header;
    headers.push_back(std::move(a));
    switch (ip6_next_header) {
        case ipv6_header::TCP:
            return parse_transport<tcp_header>(begin, end, headers);
        case ipv6_header::UDP:
            return parse_transport<udp_header>(begin, end, headers);
        case ipv6_header::IPv6:
            return parse_network<ipv6_header>(begin, end, headers);
        default:
            return parse_unknown(begin, end, headers);
    }
}

template<>
inline void parse_network<ipv4_header>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = std::make_any<ipv4_header>();
    auto& ip = std::any_cast<ipv4_header&>(a);
    *(ipv4_header_base*)&ip = *(ipv4_header_base*)begin;
    ip.len = ntohs(ip.len);
    ip.id = ntohs(ip.id);

    uint16_t tmp = *(&ip.id + 1);
    tmp = ntohs(tmp);
    ip.df = (tmp & (1 << 14)) >> 14;
    ip.mf = (tmp & (1 << 13)) >> 13;
    ip.offset = tmp;

    ip.checksum = ntohs(ip.checksum);
    std::copy(begin + sizeof(ipv4_header_base), begin + ip.header_len * 4, ip.op);

    begin += ip.header_len * 4;
    auto ip_proto = ip.proto;
    headers.push_back(std::move(a));
    switch (ip_proto) {
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
            return parse_unknown(begin, end, headers);
    }
}

template<>
inline void parse_network<arp_packet>(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = *(arp_packet*)begin;
    auto& arp = std::any_cast<arp_packet&>(a);
    arp.hardware_type = ntohs(arp.hardware_type);
    arp.proto_type = ntohs(arp.proto_type);
    arp.op = ntohs(arp.op);
    begin += sizeof(arp);
    headers.push_back(std::move(a));
}

inline void parse_datalink(const uint8_t* begin, const uint8_t* end, std::vector<std::any>& headers) {
    std::any a = *(eth_header*)begin;
    auto& eth = std::any_cast<eth_header&>(a);
    eth.len = ntohs(eth.len);
    if (eth.len <= 0x0600) {
        headers.push_back(std::vector<uint8_t>{begin, end});
        return; //不支持携带LLC层的mac帧
    }
    begin += sizeof(eth);
    auto eth_type = eth.type;
    headers.push_back(std::move(a));
    switch (eth_type) {
        case eth_header::IPv4:
            return parse_network<ipv4_header>(begin, end, headers);
        case eth_header::ARP:
            return parse_network<arp_packet>(begin, end, headers);
        case eth_header::IPv6:
            return parse_network<ipv6_header>(begin, end, headers);
        default:
            return parse_unknown(begin, end, headers);
    }
}
