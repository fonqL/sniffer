#pragma once
#include <stdint.h>
//ip协议规定大端传输

struct eth_header {
    uint8_t dst[6]; //mac不需要考虑大小端
    uint8_t src[6];
    uint16_t proto_type;
};

struct arp_header {
    uint16_t hardware_type;
    uint16_t proto_type;
    uint8_t mac_len; // = 6
    uint8_t ip_len;  // = 4
    uint16_t op;
    uint8_t src_mac[6];
    uint8_t src_ip[4];
    uint8_t dst_mac[6];
    uint8_t dst_ip[4];
};

struct ip_header {
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t ds;
    uint16_t len;
    uint16_t id;
    uint16_t : 1;
    uint16_t df : 1;
    uint16_t mf : 1;
    uint16_t offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
    uint8_t op[0]; //最多40B
};

static_assert(sizeof(ip_header) == 20, "the size of ip_header is invalid.");

struct tcp_header {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t len : 4;
    uint8_t : 4;
    struct flag_t {
        bool cwr : 1;
        bool ece : 1;
        bool urg : 1;
        bool ack : 1;
        bool psh : 1;
        bool rst : 1;
        bool syn : 1;
        bool fin : 1;
    } flag;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint8_t op[0];
};

static_assert(sizeof(tcp_header) == 20, "the size of ip_header is invalid.");

struct udp_header {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t checksum;
};

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t bytes; //由type来解释此四个byte。。。
    //数据部分长度也取决于type。。要不要做成字段呢。。
};
