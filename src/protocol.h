#pragma once

#include <QString>
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <array>
#include <stdint.h>
#include <string_view>

//

#define STR_DEC(field)                 \
    QString field##_str() const {      \
        return QString::number(field); \
    }

#define STR_HEX(field, wid, op)                           \
    QString field##_str() const {                         \
        return QString::asprintf("0x%0" #wid #op, field); \
    }

#define STR_BOOL(field)                   \
    QString field##_str() const {         \
        return field ? "Set" : "Not Set"; \
    }
//

#define REFLECT_NAME(str) \
    inline static const QString name = str;

struct blob : std::vector<uint8_t> {
    using std::vector<uint8_t>::vector;
};

using MacAddr = std::array<uint8_t, 6>;
using IPv4Addr = std::array<uint8_t, 4>;
using IPv6Addr = std::array<uint8_t, 16>;

// hack实现，因为c数组太难用了。。几乎没有值特征。。
static_assert(std::is_standard_layout_v<MacAddr>);
static_assert(std::is_standard_layout_v<IPv4Addr>);
static_assert(std::is_standard_layout_v<IPv6Addr>);

struct eth_header {
    REFLECT_NAME("eth")

    enum proto_t : uint16_t { //指定实现枚举的数据类型，正常使用即可，可以忽略
        IPv4 = 0x0800,        //外界获取的例子：eth_header::IPv4
        ARP = 0x0806,
        IPv6 = 0x86DD
    };

    MacAddr dst;
    MacAddr src;
    union {           //共用一块内存
        uint16_t len; // < 1536
        proto_t type; // >= 1536
    };

    QString srcmac() const {
        return QString::asprintf("%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
                                 src[0], src[1], src[2],
                                 src[3], src[4], src[5]);
    }
    QString dstmac() const {
        return QString::asprintf("%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
                                 dst[0], dst[1], dst[2],
                                 dst[3], dst[4], dst[5]);
    }
    QString type_str() const {
        switch (type) {
        case IPv4: return "IPv4 (0x0800)";
        case ARP: return "ARP (0x0806)";
        case IPv6: return "IPv6 (0x86DD)";
        default: return QString::asprintf("unknown (0x%04hx)", type);
        };
    }
    STR_DEC(len)
};
//外部如果用eth_header::proto_t这么长一串觉得不舒服可以自己用using/typedef起个别名

//不携带变长数据，命名为packet
struct arp_packet {
    REFLECT_NAME("arp")

    uint16_t hardware_type;
    uint16_t proto_type;
    uint8_t mac_len; // = 6
    uint8_t ip_len;  // = 4
    uint16_t op;
    MacAddr src_mac; //直接0~5输出就是正确的mac地址
    IPv4Addr src_ip;
    MacAddr dst_mac;
    IPv4Addr dst_ip;

    QString srcip() const {
        char buf[16] = {0};
        inet_ntop(AF_INET, src_ip.data(), buf, sizeof(buf));
        return QString::fromLatin1(buf, sizeof(buf));
    }
    QString dstip() const {
        char buf[16] = {0};
        inet_ntop(AF_INET, dst_ip.data(), buf, sizeof(buf));
        return QString::fromLatin1(buf, sizeof(buf));
    }
    QString op_str() const {
        switch (op) {
        case 1: return "request (1)";
        case 2: return "reply (2)";
        default: return QString::asprintf("unknown (%hd)", op);
        }
    }
    QString srcmac() const {
        return QString::asprintf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                 src_mac[0], src_mac[1], src_mac[2],
                                 src_mac[3], src_mac[4], src_mac[5]);
    }
    QString dstmac() const {
        return QString::asprintf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                 dst_mac[0], dst_mac[1], dst_mac[2],
                                 dst_mac[3], dst_mac[4], dst_mac[5]);
    }
};

struct ipv4_header_base {
    enum proto_t : uint8_t {
        ICMP = 1,
        // IPv4 = 4,
        TCP = 6,
        UDP = 17,
        // IPv6 = 41
    };

    uint8_t header_len : 4; //位域，此成员变量只占4位（虽然是uint8_t）
    uint8_t version : 4;    //version的bit位高于headerlen （编译器相关，msvc

    uint8_t ds; //旧称tos
    uint16_t len;
    uint16_t id;
    uint16_t offset : 13;
    uint16_t mf : 1;
    uint16_t df : 1;
    uint16_t : 1;
    uint8_t ttl;
    proto_t proto;
    uint16_t checksum;
    IPv4Addr src; //inet_ntop 转成字符串
    IPv4Addr dst;

    QString srcip() const {
        char buf[16] = {0};
        inet_ntop(AF_INET, src.data(), buf, sizeof(buf));
        return QString::fromLatin1(buf, sizeof(buf));
    }
    QString dstip() const {
        char buf[16] = {0};
        inet_ntop(AF_INET, dst.data(), buf, sizeof(buf));
        return QString::fromLatin1(buf, sizeof(buf));
    }
    STR_DEC(len)
    QString headerlen_str() const { return QString::number(header_len * 4); }
    STR_HEX(ds, 2, hx)
    STR_DEC(ttl)
    STR_DEC(id)
    STR_BOOL(df)
    STR_BOOL(mf)
    STR_DEC(offset)
    STR_HEX(checksum, 4, hx)
};

struct ipv4_header : ipv4_header_base {
    REFLECT_NAME("ip4")

    uint8_t op[40];
};

struct ipv6_header {
    REFLECT_NAME("ip6");

    enum header_t : uint8_t {
        TCP = 6,
        UDP = 17,
        // IPv6 = 41,
    };

    uint32_t flow_label : 20;
    uint32_t traffic_class : 8;
    uint32_t version : 4;
    uint16_t payload_len;
    header_t next_header;
    uint8_t hop_limit;
    IPv6Addr src;
    IPv6Addr dst;

    QString srcip() const {
        char buf[40] = {0};
        inet_ntop(AF_INET6, src.data(), buf, sizeof(buf));
        return QString::fromLatin1(buf, sizeof(buf));
    }
    QString dstip() const {
        char buf[40] = {0};
        inet_ntop(AF_INET6, dst.data(), buf, sizeof(buf));
        return QString::fromLatin1(buf, sizeof(buf));
    }
    STR_DEC(payload_len)
    STR_HEX(traffic_class, 2, hx)
    STR_HEX(flow_label, 5, x)
    QString next_header_str() const {
        switch (next_header) {
        case TCP: return "TCP (6)";
        case UDP: return "UDP (17)";
        default: return QString::asprintf("unknow (%hhd)", next_header);
        }
    }
    STR_DEC(hop_limit)
};

template<class K, class V>
struct entry {
    K key;
    V value;
};

template<class K, class V>
using flat_map = std::vector<entry<K, V>>;

template<class K, class T, class V>
struct entry3 {
    K key;
    T info;
    V value;
};

namespace _icmp {
template<class K, class T, class V>
using flat_map3 = std::vector<entry3<K, T, V>>;

inline static const flat_map3<uint8_t, const char*, flat_map<uint8_t, const char*>>
    info = {
        { 0,    "回应应答",   {
   {0, ""},
   }   },

        { 3, "目标不可达", {
 {0, "网络不可达"},
 {1, "主机不可达"},
 {2, "协议不可达(不支持此协议)"},
 {3, "端口不可达"},
 }     },

        { 5,       "重定向",     {
     {0, "网络重定向"},
     {1, "主机重定向"},
     {2, "tos和网络重定向"},
     {3, "tos和主机重定向"},
     } },

        { 8,    "回应请求",   {
   {0, ""},
   }   },

        {11,          "超时",      {
      {0, "跳数/生存期耗尽"},
      {1, "碎片重组超时"},
      }},
};

inline std::pair<QString, QString> type_code_str(uint8_t type, uint8_t code) {
    auto [s1, s2] = [&]() -> std::pair<const char*, const char*> {
        for (auto& i: info) {
            if (i.key == type) {
                for (auto& j: i.value) {
                    if (j.key == code)
                        return {i.info, j.value};
                }
                return {i.info, "未知"};
            }
        }
        return {"未知", ""};
    }();
    return {
        QString::asprintf("%s (%hhu)", s1, type),
        QString::asprintf("%s (%hhu)", s2, code)};
}

} // namespace _icmp

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

    std::pair<QString, QString> type_code_str() const {
        return _icmp::type_code_str(type, code);
    }
    STR_HEX(checksum, 4, hx)
};

struct icmp_packet : icmp_packet_base {
    REFLECT_NAME("icmp")

    blob data;
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

        STR_BOOL(fin)
        STR_BOOL(syn)
        STR_BOOL(rst)
        STR_BOOL(psh)
        STR_BOOL(ack)
        STR_BOOL(urg)
        STR_BOOL(ece)
        STR_BOOL(cwr)
    } flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;

    uint16_t is_dns() const { return std::min(src, dst) == 53; }

    STR_DEC(src)
    STR_DEC(dst)
    STR_DEC(seq)
    STR_DEC(ack)
    QString header_len_str() const {
        return QString::number(header_len * 4);
    }
    STR_DEC(window_size)
    STR_HEX(checksum, 4, hx)
    STR_DEC(urgent_ptr)
};

struct tcp_header : tcp_header_base {
    REFLECT_NAME("tcp")

    uint8_t op[40];
};

struct udp_header {
    REFLECT_NAME("udp")

    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t checksum;

    uint16_t is_dns() const { return std::min(src, dst) == 53; }

    STR_DEC(src)
    STR_DEC(dst)
    STR_DEC(len)
    STR_HEX(checksum, 4, hx)
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

        QString qr_str() const {
            if (qr == 0) {
                return "查询请求 (0)";
            } else {
                return "响应 (1)";
            }
        }
        QString opcode_str() const {
            if (opcode == 0) {
                return "标准查询 (0)";
            } else if (opcode == 1) {
                return "反向查询 (1)";
            } else if (opcode == 2) {
                return "服务器状态请求 (2)";
            } else {
                return QString::asprintf("未知 (%hd)", opcode);
            }
        }
        QString aa_str() const {
            if (aa == 0) {
                return "非权威服务器 (0)";
            } else {
                return "权威服务器 (1)";
            }
        }
        QString tc_str() const {
            if (tc == 0) {
                return "未截断 (0)";
            } else {
                return "已截断(1)";
            }
        }
        STR_BOOL(rd)
        QString ra_str() const {
            if (ra == 0) {
                return "不支持递归查询 (0)";
            } else {
                return "支持递归查询 (1)";
            }
        }
        QString rcode_str() const {
            if (rcode == 0) {
                return "无错误 (0)";
            } else if (rcode == 1) {
                return "格式错误 (1)";
            } else if (rcode == 2) {
                return "服务器失败 (2)";
            } else if (rcode == 3) {
                return "名字错误 (3)";
            } else if (rcode == 4) {
                return "类型不支持 (4)";
            } else if (rcode == 5) {
                return "拒绝应答 (5)";
            } else {
                return QString::asprintf("未知 (%hd)", rcode);
            }
        }

    } flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;

    STR_DEC(id)
    STR_DEC(questions)
    STR_DEC(answer_rrs)
    STR_DEC(authority_rrs)
    STR_DEC(additional_rrs)
};

struct dns_packet : dns_packet_base {
    REFLECT_NAME("dns")

    blob data;
};

static_assert(sizeof(eth_header) == 14); //验证
static_assert(sizeof(arp_packet) == 28);
static_assert(sizeof(ipv4_header_base) == 20);
static_assert(sizeof(ipv6_header) == 40);
static_assert(sizeof(icmp_packet_base) == 8);
static_assert(sizeof(tcp_header_base) == 20);
static_assert(sizeof(udp_header) == 8);
static_assert(sizeof(dns_packet_base) == 12);

#undef REFLECT_NAME
#undef STR_DEC
#undef STR_HEX
#undef STR_BOOL

// PROTO_CASE(tcp_header_base::flag_t) {
//     FIELD_CASE(cwr);
//     FIELD_CASE(ece);
//     FIELD_CASE(urg);
//     FIELD_CASE(ack);
//     FIELD_CASE(psh);
//     FIELD_CASE(rst);
//     FIELD_CASE(syn);
//     FIELD_CASE(fin);
// }

template<class... Ts>
struct type_list {};

using ValidProtos = type_list<eth_header,
                              arp_packet,
                              ipv4_header,
                              ipv6_header,
                              icmp_packet,
                              tcp_header,
                              udp_header,
                              dns_packet>;
