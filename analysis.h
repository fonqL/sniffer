#pragma once

#include "handle_packet.h"
#include "protocol.h"

//计数类
struct Count {
    std::vector<int> ipv4_c;
    std::vector<int> ipv6_c;
    std::vector<int> arp_c;
    std::vector<int> other_c;
    std::vector<int> icmp_c;
    std::vector<int> tcp_c;
    std::vector<int> udp_c;
    std::vector<int> other_header_c;
    std::vector<int> dns_c;
    std::vector<int> other_app_c;
};

struct Count_time {
    QDateTime time;
    int ipv4;
    int ipv6;
    int arp;
    int other;
    int icmp;
    int tcp;
    int udp;
    int other_h;
    int dns;
    int other_a;
};

//用于分析的类，直接用packet创建，然后用其成员变量
class analysis {
public:
    //通用的属性：
    // 时间
    QString time;
    // 类型
    QString type;
    // 包长度,单位字节
    QString len;
    // 源mac
    QString srcMac;
    QString desMac;
    QString srcIp = "";
    QString desIp = "";
    // 协议类型
    QString header = "";
    //应用层
    QString app = "";
    //源数据
    QString rawdata = "空";

    // 协议：
    // 处理ipv4
    ipv4_header ipv4;
    // 处理ipv6
    ipv6_header ipv6;
    // 处理arp
    arp_packet arp;

    // 处理icmp
    icmp_packet icmp;
    // 处理tcp
    tcp_header tcp;
    // 处理udp
    udp_header udp;

    //处理dns
    dns_packet dns;

    analysis(const std::vector<std::any>& packet) {
        simple_info info = std::any_cast<simple_info>(packet[0]);
        eth_header eth = std::any_cast<eth_header>(packet[1]);

        std::vector<char> rawbuf(info.raw_data.size() * 5 * sizeof(char), '\0');
        int offset = 0;
        for (int i = 0; i < info.raw_data.size(); i++) {
            offset += sprintf(rawbuf.data() + offset, "%02x ", info.raw_data[i]);
        }
        rawdata = QString::fromLocal8Bit(rawbuf.data(), offset);

        len = QString::number((int)eth.len);
        srcMac = QString::asprintf("%02x-%02x-%02x-%02x-%02x-%02x",
                                   eth.src[0], eth.src[1], eth.src[2],
                                   eth.src[3], eth.src[4], eth.src[5]);
        desMac = QString::asprintf("%02x-%02x-%02x-%02x-%02x-%02x",
                                   eth.dst[0], eth.dst[1], eth.dst[2],
                                   eth.dst[3], eth.dst[4], eth.dst[5]);

        time = info.t.toString("hh:mm:ss");

        if (packet[2].type() == typeid(ipv4_header)) {
            type = "IPv4";
            header = "ipv4";
            ipv4 = std::any_cast<ipv4_header>(packet[2]);
            char buf1[20] = {0};
            inet_ntop(AF_INET, ipv4.src, buf1, sizeof(buf1));
            srcIp = QString::fromStdString(buf1);
            char buf2[20] = {0};
            inet_ntop(AF_INET, ipv4.dst, buf2, sizeof(buf2));
            desIp = QString::fromStdString(buf2);
            len = QString::number((int)ipv4.len);
        } else if (packet[2].type() == typeid(arp_packet)) {
            type = "ARP";
            header = "ARP";
            arp = std::any_cast<arp_packet>(packet[2]);
            char buf1[20] = {0};
            inet_ntop(AF_INET, arp.src_ip, buf1, sizeof(buf1));
            srcIp = QString::fromStdString(buf1);
            char buf2[20] = {0};
            inet_ntop(AF_INET, arp.dst_ip, buf2, sizeof(buf2));
            desIp = QString::fromStdString(buf2);
            len = QString::number((int)arp.ip_len);
        } else if (packet[2].type() == typeid(ipv6_header)) {
            type = "IPv6";
            header = "ipv4";
            ipv6 = std::any_cast<ipv6_header>(packet[2]);
            char buf1[50] = {0};
            inet_ntop(AF_INET6, ipv6.src, buf1, sizeof(buf1));
            srcIp = QString::fromStdString(buf1);
            char buf2[50] = {0};
            inet_ntop(AF_INET6, ipv6.dst, buf2, sizeof(buf2));
            desIp = QString::fromStdString(buf2);
            len = QString::number((int)ipv6.payload_len);
        } else {
            type = "other";
            header = "other";
        }

        if (packet.size() >= 4) {
            if (packet[3].type() == typeid(icmp_packet)) {
                header = "icmp";
                icmp = std::any_cast<icmp_packet>(packet[3]);
            } else if (packet[3].type() == typeid(tcp_header)) {
                header = "tcp";
                tcp = std::any_cast<tcp_header>(packet[3]);
            } else if (packet[3].type() == typeid(udp_header)) {
                header = "udp";
                udp = std::any_cast<udp_header>(packet[3]);
            } else {
                header = "other";
            }
        }
        if (packet.size() >= 5) {
            if (packet[4].type() == typeid(dns_packet)) {
                app = "dns";
                dns = std::any_cast<dns_packet>(packet[4]);
            } else {
                app = "other";
            }
        }
    }
};
