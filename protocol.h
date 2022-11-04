#pragma once

#include <stdint.h>
#include <string_view>
#include <vector>

struct eth_header {
    enum proto_t : uint16_t { //指定实现枚举的数据类型，正常使用即可，可以忽略
        IPv4 = 0x0800,        //外界获取的例子：eth_header::IPv4
        ARP = 0x0806,
        IPv6 = 0x86DD
    };

    uint8_t dst[6];
    uint8_t src[6];
    union {           //共用一块内存
        uint16_t len; // < 1536
        proto_t type; // >= 1536
    };
};
//外部如果用eth_header::proto_t这么长一串觉得不舒服可以自己用using/typedef起个别名

//不携带变长数据，命名为packet
struct arp_packet {
    uint16_t hardware_type;
    uint16_t proto_type;
    uint8_t mac_len; // = 6
    uint8_t ip_len;  // = 4
    uint16_t op;
    uint8_t src_mac[6]; //直接0~5输出就是正确的mac地址
    uint8_t src_ip[4];
    uint8_t dst_mac[6];
    uint8_t dst_ip[4];
};

struct ipv4_header_base {
    enum proto_t : uint8_t {
        ICMP = 1,
        IPv4 = 4,
        TCP = 6,
        UDP = 17,
        IPv6 = 41
    };

    uint8_t header_len : 4; //位域，此成员变量只占4位（虽然是uint8_t）
    uint8_t version : 4;    //version的bit位高于headerlen （编译器相关，msvc

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
    uint8_t src[4]; //inet_ntop 转成字符串
    uint8_t dst[4];
};

struct ipv4_header : ipv4_header_base {
    uint8_t op[40];
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
    header_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
};

struct icmp_packet_base {
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
    //数据部分长度也取决于type。。
    //wireshark也把解析的数据归于icmp内而不是与icmp同级
};

struct icmp_packet : icmp_packet_base {
    std::vector<uint8_t> data;
};

struct tcp_header_base {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t : 4;
    uint8_t header_len : 4;
    struct flag_t {
        uint8_t fin : 1;
        uint8_t syn : 1;
        uint8_t rst : 1;
        uint8_t psh : 1;
        uint8_t ack : 1;
        uint8_t urg : 1;
        uint8_t ece : 1;
        uint8_t cwr : 1;
    } flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;

    uint16_t type() { return std::min(src, dst); }
};

struct tcp_header : tcp_header_base {
    uint8_t op[40];
};

struct udp_header {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t checksum;

    uint16_t type() { return std::min(src, dst); }
};

//应用层类型的判断要靠端口。。源端口与目的端口都要判断。。
//长度也是靠tcp/udp里的长度判断
//port: 53
struct dns_packet_base {
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
};

struct dns_packet : dns_packet_base {
    std::vector<uint8_t> data;
};

// enum class query_t : uint8_t { //查询的资源记录类型。
//     A = 0x01,                  //指定计算机 IP 地址。
//     NS = 0x02,                 //指定用于命名区域的 DNS 名称服务器。
//     MD = 0x03,                 //指定邮件接收站（此类型已经过时了，使用MX代替）
//     MF = 0x04,                 //指定邮件中转站（此类型已经过时了，使用MX代替）
//     CNAME = 0x05,              //指定用于别名的规范名称。
//     SOA = 0x06,                //指定用于 DNS 区域的“起始授权机构”。
//     MB = 0x07,                 //指定邮箱域名。
//     MG = 0x08,                 //指定邮件组成员。
//     MR = 0x09,                 //指定邮件重命名域名。
//     NUL = 0x0A,                //指定空的资源记录
//     WKS = 0x0B,                //描述已知服务。
//     PTR = 0x0C,                //如果查询是 IP 地址，则指定计算机名；否则指定指向其它信息的指针。
//     HINFO = 0x0D,              //指定计算机 CPU 以及操作系统类型。
//     MINFO = 0x0E,              //指定邮箱或邮件列表信息。
//     MX = 0x0F,                 //指定邮件交换器。
//     TXT = 0x10,                //指定文本信息。
//     UINFO = 0x64,              //指定用户信息。
//     UID = 0x65,                //指定用户标识符。
//     GID = 0x66,                //指定组名的组标识符。
//     ANY = 0xFF                 //指定所有数据类型。
// };

// enum class query_class : uint8_t { //指定信息的协议组。
//     IN = 0x01,                     //指定 Internet 类别。
//     CSNET = 0x02,                  //指定 CSNET 类别。（已过时）
//     CHAOS = 0x03,                  //指定 Chaos 类别。
//     HESIOD = 0x04,                 //指定 MIT Athena Hesiod 类别。
//     ANY = 0xFF                     //指定任何以前列出的通配符。
// };

static_assert(sizeof(eth_header) == 14); //验证
static_assert(sizeof(arp_packet) == 28);
static_assert(sizeof(ipv4_header_base) == 20);
static_assert(sizeof(ipv6_header) == 40);
static_assert(sizeof(icmp_packet_base) == 8);
static_assert(sizeof(tcp_header_base) == 20);
static_assert(sizeof(udp_header) == 8);
static_assert(sizeof(dns_packet_base) == 12);

//

#define STR(str) #str // STR(abc) == "abc"

#define REFLECT(type)    \
    template<typename R> \
    R get(const type& x, std::string_view str)

#define FIELD(field) \
    if (str == STR(field)) return (R)(x.field)

REFLECT(eth_header) {
    FIELD(dst);
    FIELD(src);
    FIELD(len);
    FIELD(type);
}

REFLECT(arp_packet) {
    FIELD(hardware_type);
    FIELD(proto_type);
    FIELD(mac_len);
    FIELD(ip_len);
    FIELD(op);
    FIELD(src_mac);
    FIELD(src_ip);
    FIELD(dst_mac);
    FIELD(dst_ip);
}

REFLECT(ipv4_header) {
    FIELD(version);
    FIELD(header_len);
    FIELD(ds);
    FIELD(len);
    FIELD(id);
    FIELD(df);
    FIELD(mf);
    FIELD(offset);
    FIELD(ttl);
    FIELD(proto);
    FIELD(checksum);
    FIELD(src);
    FIELD(dst);
    FIELD(op);
}

REFLECT(ipv6_header) {
    FIELD(version);
    FIELD(traffic_class);
    FIELD(flow_label);
    FIELD(payload_len);
    FIELD(next_header);
    FIELD(hop_limit);
    FIELD(src);
    FIELD(dst);
}

REFLECT(icmp_packet) {
    FIELD(type);
    FIELD(code);
    FIELD(checksum);
    FIELD(field);
    FIELD(data);
}

REFLECT(tcp_header_base::flag_t) {
    FIELD(cwr);
    FIELD(ece);
    FIELD(urg);
    FIELD(ack);
    FIELD(psh);
    FIELD(rst);
    FIELD(syn);
    FIELD(fin);
}

REFLECT(tcp_header) {
    FIELD(src);
    FIELD(dst);
    FIELD(seq);
    FIELD(ack);
    FIELD(header_len);
    FIELD(flags);
    FIELD(window_size);
    FIELD(checksum);
    FIELD(urgent_ptr);
    FIELD(op);
}

REFLECT(udp_header) {
    FIELD(src);
    FIELD(dst);
    FIELD(len);
    FIELD(checksum);
}

REFLECT(dns_packet) {
    FIELD(id);
    FIELD(flags);
    FIELD(questions);
    FIELD(answer_rrs);
    FIELD(authority_rrs);
    FIELD(additional_rrs);
    FIELD(data);
}

#undef FIELD
#undef REFLECT
#undef STR
