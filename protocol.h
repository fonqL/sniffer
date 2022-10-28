#pragma once
#pragma warning(disable : 4200)

#include <stdint.h>

//ip协议规定大端传输

struct eth_header {
    enum proto_t : uint16_t {
        IPv4 = 0x0800,
        ARP = 0x0806,
        IPv6 = 0x86DD
    };

    uint8_t dst[6]; //mac不需要考虑大小端
    uint8_t src[6];
    union {
        uint16_t len; // < 1536
        proto_t type; // >= 1536
    };
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

struct ipv4_header {
    enum proto_t : uint8_t {
        ICMP = 1,
        IPv4 = 4,
        TCP = 6,
        UDP = 17,
        IPv6 = 41
    };

    uint8_t version : 4;
    uint8_t header_len : 4;
    uint8_t ds; //旧称tos
    uint16_t len;
    uint16_t id;
    uint16_t : 1;
    uint16_t df : 1;
    uint16_t mf : 1;
    uint16_t offset : 13;
    uint8_t ttl;
    proto_t proto;
    uint16_t checksum;
    uint8_t src[4]; //不考虑大小端
    uint8_t dst[4];
    uint8_t op[]; //最多40 Byte
};

struct ipv6_header {
    enum header_t : uint8_t {
        TCP = 6,
        UDP = 17,
        IPv6 = 41,
    };

    uint32_t version : 4;
    uint32_t traffic_class : 8;
    uint32_t flow_label : 20;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
    uint8_t header[];
};

struct icmp_packet {
    enum type_t : uint8_t {
        EHCO_REPLY = 0,
        UNREACHABLE = 3,
        ECHO_REQUEST = 8,
        TIME_EXCEED = 11,
    };

    uint8_t type; //先不做成枚举。。也不知道怎么处理。。
    uint8_t code;
    uint16_t checksum;
    uint32_t field; //解释权归type所有。。
    uint8_t data[];
    //数据部分长度也取决于type。。
    //wireshark也把解析的数据归于icmp内而不是与icmp同级
};

struct tcp_header {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t len : 4;
    uint8_t : 4;
    struct flag_t {
        uint8_t cwr : 1;
        uint8_t ece : 1;
        uint8_t urg : 1;
        uint8_t ack : 1;
        uint8_t psh : 1;
        uint8_t rst : 1;
        uint8_t syn : 1;
        uint8_t fin : 1;
    } flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint8_t op[];
};

struct udp_header {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t checksum;
};

struct dns_packet {
    uint16_t id;
    struct flag_t {
        uint16_t qr : 1;
        uint16_t opcode : 4;
        uint16_t aa : 1;
        uint16_t tc : 1;
        uint16_t rd : 1;
        uint16_t ra : 1;
        uint16_t z : 3;
        uint16_t rcode : 4;
    } flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
    uint8_t data[];
};

enum class query_t : uint8_t { //查询的资源记录类型。
    A = 0x01,                  //指定计算机 IP 地址。
    NS = 0x02,                 //指定用于命名区域的 DNS 名称服务器。
    MD = 0x03,                 //指定邮件接收站（此类型已经过时了，使用MX代替）
    MF = 0x04,                 //指定邮件中转站（此类型已经过时了，使用MX代替）
    CNAME = 0x05,              //指定用于别名的规范名称。
    SOA = 0x06,                //指定用于 DNS 区域的“起始授权机构”。
    MB = 0x07,                 //指定邮箱域名。
    MG = 0x08,                 //指定邮件组成员。
    MR = 0x09,                 //指定邮件重命名域名。
    NUL = 0x0A,                //指定空的资源记录
    WKS = 0x0B,                //描述已知服务。
    PTR = 0x0C,                //如果查询是 IP 地址，则指定计算机名；否则指定指向其它信息的指针。
    HINFO = 0x0D,              //指定计算机 CPU 以及操作系统类型。
    MINFO = 0x0E,              //指定邮箱或邮件列表信息。
    MX = 0x0F,                 //指定邮件交换器。
    TXT = 0x10,                //指定文本信息。
    UINFO = 0x64,              //指定用户信息。
    UID = 0x65,                //指定用户标识符。
    GID = 0x66,                //指定组名的组标识符。
    ANY = 0xFF                 //指定所有数据类型。
};

enum class query_class : uint8_t { //指定信息的协议组。
    IN = 0x01,                     //指定 Internet 类别。
    CSNET = 0x02,                  //指定 CSNET 类别。（已过时）
    CHAOS = 0x03,                  //指定 Chaos 类别。
    HESIOD = 0x04,                 //指定 MIT Athena Hesiod 类别。
    ANY = 0xFF                     //指定任何以前列出的通配符。
};

static_assert(sizeof(eth_header) == 14);
static_assert(sizeof(arp_header) == 28);
static_assert(sizeof(ipv4_header) == 20);
static_assert(sizeof(ipv6_header) == 40);
static_assert(sizeof(tcp_header) == 20);
static_assert(sizeof(icmp_packet) == 8);
static_assert(sizeof(dns_packet) == 12);
