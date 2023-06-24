#include "packet.h"
#include <WinSock2.h>

// 解析报文相关
// ..挺迷惑的。。居然真的会收到不符合协议约定的包崩溃程序。。

void packet::parse_unknown(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin > end)
        return;
    pkt.push_back(blob{begin, end});
}

template<>
void packet::parse_application<dns_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(dns_packet_base) > end)
        return;
    dns_packet dns{
        .data{begin + sizeof(dns_packet_base), end}
    };
    std::memcpy(static_cast<dns_packet_base*>(&dns), begin, sizeof(dns_packet_base)); // 这是合法的“隐式创建”，见cpprefer的std::memcpy页面

    dns.id = ntohs(dns.id);
    dns.flags = std::bit_cast<dns_packet_base::flag_t>(ntohs(std::bit_cast<uint16_t>(dns.flags)));
    dns.questions = ntohs(dns.questions);
    dns.answer_rrs = ntohs(dns.answer_rrs);
    dns.authority_rrs = ntohs(dns.authority_rrs);
    dns.additional_rrs = ntohs(dns.additional_rrs);

    pkt.push_back(std::move(dns));
}

template<>
void packet::parse_transport<tcp_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(tcp_header_base) > end)
        return;
    tcp_header tcp;
    std::memcpy(static_cast<tcp_header_base*>(&tcp), begin, sizeof(tcp_header_base));
    tcp.src = ntohs(tcp.src);
    tcp.dst = ntohs(tcp.dst);
    tcp.seq = ntohl(tcp.seq);
    tcp.ack = ntohl(tcp.ack);
    tcp.window_size = ntohs(tcp.window_size);
    tcp.checksum = ntohs(tcp.checksum);
    tcp.urgent_ptr = ntohs(tcp.urgent_ptr);

    [[unlikely]] if (sizeof(tcp_header_base) / 4 > tcp.header_len || begin + tcp.header_len * 4 > end)
        return;
    std::copy(begin + sizeof(tcp_header_base), begin + tcp.header_len * 4, tcp.op);

    begin += tcp.header_len * 4;

    bool f = tcp.is_dns();
    pkt.push_back(std::move(tcp));
    if (f) {
        return parse_application<dns_packet>(begin, end, pkt);
    } else {
        return parse_unknown(begin, end, pkt);
    }
}

template<>
void packet::parse_transport<udp_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(begin) > end)
        return;
    udp_header udp;
    std::memcpy(&udp, begin, sizeof(udp));

    udp.src = ntohs(udp.src);
    udp.dst = ntohs(udp.dst);
    udp.len = ntohs(udp.len);
    udp.checksum = ntohs(udp.checksum);

    begin += sizeof(udp);

    bool f = udp.is_dns();
    pkt.push_back(std::move(udp));
    if (f) {
        return parse_application<dns_packet>(begin, end, pkt);
    } else {
        return parse_unknown(begin, end, pkt);
    }
}

template<>
void packet::parse_transport<icmp_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(icmp_packet_base) > end)
        return;
    icmp_packet icmp{
        .data{begin + sizeof(icmp_packet_base), end}
    };
    std::memcpy(static_cast<icmp_packet_base*>(&icmp), begin, sizeof(icmp_packet_base));
    icmp.checksum = ntohs(icmp.checksum);
    icmp.field = ntohl(icmp.field);

    pkt.push_back(std::move(icmp));
}

template<>
void packet::parse_network<ipv6_header>(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(ipv6_header) > end)
        return;
    ipv6_header ip6;
    std::memcpy(&ip6, begin, sizeof(ipv6_header));

    uint32_t tmp;
    std::memcpy(&tmp, &ip6, sizeof(tmp));
    tmp = ntohl(tmp);
    ip6.version = (tmp & (0xfU << 28)) >> 28;
    ip6.traffic_class = (tmp & (0xffU << 20)) >> 20;
    ip6.flow_label = tmp;

    ip6.payload_len = ntohs(ip6.payload_len);

    begin += sizeof(ip6); //这里没错，ipv6不是变长的
    auto ip6_next_header = ip6.next_header;
    pkt.push_back(std::move(ip6));
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
    [[unlikely]] if (begin + sizeof(ipv4_header_base) > end)
        return;
    ipv4_header ip;
    std::memcpy(static_cast<ipv4_header_base*>(&ip), begin, sizeof(ipv4_header_base));
    ip.len = ntohs(ip.len);
    ip.id = ntohs(ip.id);

    uint16_t tmp = *(&ip.id + 1);
    tmp = ntohs(tmp);
    ip.df = (tmp & (1u << 14)) >> 14;
    ip.mf = (tmp & (1u << 13)) >> 13;
    ip.offset = tmp;

    ip.checksum = ntohs(ip.checksum);
    [[unlikely]] if (sizeof(ipv4_header_base) / 4 > ip.header_len || begin + ip.header_len * 4 > end)
        return;
    std::copy(begin + sizeof(ipv4_header_base), begin + ip.header_len * 4, ip.op);

    begin += ip.header_len * 4;
    auto ip_proto = ip.proto;
    pkt.push_back(std::move(ip));
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
    [[unlikely]] if (begin + sizeof(arp_packet) > end)
        return;
    arp_packet arp;
    memcpy(&arp, begin, sizeof(arp));
    arp.hardware_type = ntohs(arp.hardware_type);
    arp.proto_type = ntohs(arp.proto_type);
    arp.op = ntohs(arp.op);
    begin += sizeof(arp);
    pkt.push_back(std::move(arp));
}

void packet::parse_datalink(const uint8_t* begin, const uint8_t* end, packet& pkt) {
    [[unlikely]] if (begin + sizeof(eth_header) > end)
        return;
    eth_header eth;
    memcpy(&eth, begin, sizeof(eth));
    eth.len = ntohs(eth.len);
    begin += sizeof(eth);
    auto eth_type = eth.type;
    pkt.push_back(std::move(eth));
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
