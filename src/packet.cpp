#include "packet.h"
#include <WinSock2.h>

// 解析报文相关

void packet::parse_unknown(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin >= end + 1)
        return;
    pkt.add(blob{static_cast<uint16_t>(end - begin)}, begin, end);
}

template<>
void packet::parse_application<dns_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(dns_packet_base) >= end + 1)
        return;
    auto& dns = pkt.add(dns_packet{}, begin + sizeof(dns_packet_base), end);
    (dns_packet_base&)dns = *(dns_packet_base*)begin;

    dns.id = ntohs(dns.id);

    uint16_t tmp = *(uint16_t*)&dns.flags;
    tmp = ntohs(tmp);
    dns.flags = *(dns_packet::flag_t*)&tmp;

    dns.questions = ntohs(dns.questions);
    dns.answer_rrs = ntohs(dns.answer_rrs);
    dns.authority_rrs = ntohs(dns.authority_rrs);
    dns.additional_rrs = ntohs(dns.additional_rrs);

    dns.len = end - (begin + sizeof(dns_packet_base));
}

template<>
void packet::parse_transport<tcp_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(tcp_header_base) >= end + 1)
        return;
    auto& tcp = pkt.add(tcp_header{});
    (tcp_header_base&)tcp = *(tcp_header_base*)begin;
    tcp.src = ntohs(tcp.src);
    tcp.dst = ntohs(tcp.dst);
    tcp.seq = ntohl(tcp.seq);
    tcp.ack = ntohl(tcp.ack);
    tcp.window_size = ntohs(tcp.window_size);
    tcp.checksum = ntohs(tcp.checksum);
    tcp.urgent_ptr = ntohs(tcp.urgent_ptr);

    if (begin + tcp.header_len * 4 >= end + 1)
        return;
    std::copy(begin + sizeof(tcp_header_base), begin + tcp.header_len * 4, tcp.op);

    begin += tcp.header_len * 4;
    if (tcp.is_dns()) {
        return parse_application<dns_packet>(begin, end, pkt);
    } else {
        return parse_unknown(begin, end, pkt);
    }
}

template<>
void packet::parse_transport<udp_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(begin) >= end + 1)
        return;
    auto& udp = pkt.add(*(udp_header*)begin); //reinterpret+const

    udp.src = ntohs(udp.src);
    udp.dst = ntohs(udp.dst);
    udp.len = ntohs(udp.len);
    udp.checksum = ntohs(udp.checksum);

    begin += sizeof(udp);
    if (udp.is_dns()) {
        return parse_application<dns_packet>(begin, end, pkt);
    } else {
        return parse_unknown(begin, end, pkt);
    }
}

template<>
void packet::parse_transport<icmp_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(icmp_packet_base) >= end + 1)
        return;
    auto& icmp = pkt.add(icmp_packet{}, begin + sizeof(icmp_packet_base), end);
    (icmp_packet_base&)icmp = *(icmp_packet_base*)begin;
    icmp.checksum = ntohs(icmp.checksum);
    icmp.field = ntohl(icmp.field);

    icmp.len = end - (begin + sizeof(icmp_packet_base));
}

template<>
void packet::parse_network<ipv6_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(ipv6_header) >= end + 1)
        return;
    auto& ip6 = pkt.add(*(ipv6_header*)begin); //reinterpret+const

    uint32_t tmp = *(uint32_t*)&ip6;
    tmp = ntohl(tmp);
    ip6.version = (tmp & (0xfu << 28)) >> 28;
    ip6.traffic_class = (tmp & (0xff << 20)) >> 20;
    ip6.flow_label = tmp;

    ip6.payload_len = ntohs(ip6.payload_len);
    begin += sizeof(ip6); //这里没错，ipv6不是变长的
    auto ip6_next_header = ip6.next_header;
    switch (ip6_next_header) {
    case ipv6_header::TCP:
        return parse_transport<tcp_header>(begin, end, pkt);
    case ipv6_header::UDP:
        return parse_transport<udp_header>(begin, end, pkt);
    // case ipv6_header::IPv6:
    //     return parse_network<ipv6_header>(begin, end, pkt);
    default:
        return parse_unknown(begin, end, pkt);
    }
}

template<>
void packet::parse_network<ipv4_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(ipv4_header_base) >= end + 1)
        return;
    auto& ip = pkt.add(ipv4_header{});
    (ipv4_header_base&)ip = *(ipv4_header_base*)begin;
    ip.len = ntohs(ip.len);
    ip.id = ntohs(ip.id);

    uint16_t tmp = *(&ip.id + 1);
    tmp = ntohs(tmp);
    ip.df = (tmp & (1 << 14)) >> 14;
    ip.mf = (tmp & (1 << 13)) >> 13;
    ip.offset = tmp;

    ip.checksum = ntohs(ip.checksum);
    if (begin + ip.header_len * 4 >= end + 1)
        return;
    std::copy(begin + sizeof(ipv4_header_base), begin + ip.header_len * 4, ip.op);

    begin += ip.header_len * 4;
    auto ip_proto = ip.proto;
    switch (ip_proto) {
    case ipv4_header::ICMP:
        return parse_transport<icmp_packet>(begin, end, pkt);
    // case ipv4_header::IPv4:
    //     return parse_network<ipv4_header>(begin, end, pkt);
    case ipv4_header::TCP:
        return parse_transport<tcp_header>(begin, end, pkt);
    case ipv4_header::UDP:
        return parse_transport<udp_header>(begin, end, pkt);
    // case ipv4_header::IPv6:
    //     return parse_network<ipv6_header>(begin, end, pkt);
    default:
        return parse_unknown(begin, end, pkt);
    }
}

template<>
void packet::parse_network<arp_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(arp_packet) >= end + 1)
        return;
    auto& arp = pkt.add(*(arp_packet*)begin); // reinterpret+const
    arp.hardware_type = ntohs(arp.hardware_type);
    arp.proto_type = ntohs(arp.proto_type);
    arp.op = ntohs(arp.op);
    begin += sizeof(arp);
}

void packet::parse_datalink(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(eth_header) >= end + 1)
        return;
    auto& eth = pkt.add(*(eth_header*)begin);
    eth.len = ntohs(eth.len);
    begin += sizeof(eth);
    auto eth_type = eth.type;
    switch (eth_type) {
    case eth_header::IPv4:
        return parse_network<ipv4_header>(begin, end, pkt);
    case eth_header::ARP:
        return parse_network<arp_packet>(begin, end, pkt);
    case eth_header::IPv6:
        return parse_network<ipv6_header>(begin, end, pkt);
    default:
        return parse_unknown(begin, end, pkt);
    }
}

packet packet::parse_packet(const uint8_t* begin, const uint8_t* end) {
    packet ret;
    parse_datalink(begin, end, ret);
    return ret;
}
