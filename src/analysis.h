#pragma once

// #include "ProxyIntVector.h"
#include <QDatetime>

//计数类
struct Count {
    std::vector<size_t> ipv4_c;
    std::vector<size_t> ipv6_c;
    std::vector<size_t> arp_c;
    // 统计ip层其他协议
    std::vector<size_t> other_c;
    std::vector<size_t> icmp_c;
    std::vector<size_t> tcp_c;
    std::vector<size_t> udp_c;
    // 统计tcp层其他协议
    std::vector<size_t> other_header_c;
    std::vector<size_t> dns_c;
    // 统计应用层其他协议
    std::vector<size_t> other_app_c;
};

struct Count_time {
    QDateTime time;
    size_t ipv4;
    size_t ipv6;
    size_t arp;
    size_t other;
    size_t icmp;
    size_t tcp;
    size_t udp;
    size_t other_h;
    size_t dns;
    size_t other_a;
};
