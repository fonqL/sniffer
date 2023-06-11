#pragma once
#include "protocol.h"
#include "LLVM/SmallVector.h"
#include <QDateTime>
#include <any>
#include <stdexcept>
#include <typeindex>
#include <vector>

class QDataStream;

class packet {
private:
    // 随便选了个4
    llvm_vecsmall::SmallVector<std::any, 4> layers;

public:
    packet() noexcept {};
    packet(packet&& x) noexcept : layers(std::move(x.layers)) {}
    packet& operator=(packet&& x) noexcept {
        layers = std::move(x.layers);
        return *this;
    };
    packet(const packet&) = delete;
    packet& operator=(const packet&) = delete;
    ~packet() = default;

public:
    size_t size() const noexcept { return layers.size(); }
    bool empty() const noexcept { return layers.empty(); }

public:
    template<class T>
    void push_back(T&& x) { layers.push_back(std::forward<T>(x)); }

    void pop_back() { layers.pop_back(); }

    template<typename T>
    const T* get() const noexcept {
        for (auto& x: layers) {
            auto* res = std::any_cast<T>(&x);
            if (res != nullptr)
                return res;
        }
        return nullptr;
    }

    template<typename T>
    const T& at() const {
        [[likely]] if (auto* res = get<T>()) {
            return *res;
        } else {
            throw std::out_of_range("packet::at");
        }
    }

    QString highest_proto() const {
        auto it = layers.end();
        --it; // it -> layers.back;
        if (it->type() == typeid(blob)) {
            --it;
        }
        auto& x = it->type();
        if (x == typeid(eth_header))
            return "Eth";
        else if (x == typeid(arp_packet))
            return "ARP";
        else if (x == typeid(ipv4_header))
            return "IPv4";
        else if (x == typeid(ipv6_header))
            return "IPv6";
        else if (x == typeid(icmp_packet))
            return "ICMP";
        else if (x == typeid(tcp_header))
            return "TCP";
        else if (x == typeid(udp_header))
            return "UDP";
        else if (x == typeid(dns_packet))
            return "DNS";
        else [[unlikely]]
            throw std::runtime_error{"invalid status"};
    }

    void traverse(auto f) const {
        handle<eth_header>(layers.begin(), std::move(f));
    }

private:
    template<class T>
    void handle(decltype(layers)::const_iterator it, auto f) const {
        [[unlikely]] if (it == layers.end())
            return;
        auto& lay = std::any_cast<const T&>(*it);
        ++it;
        f(lay);
        if constexpr (std::is_same_v<T, eth_header>) {
            switch (lay.type) {
            case eth_header::IPv4:
                return handle<ipv4_header>(it, std::move(f));
            case eth_header::ARP:
                return handle<arp_packet>(it, std::move(f));
            case eth_header::IPv6:
                return handle<ipv6_header>(it, std::move(f));
            default:
                return handle<blob>(it, std::move(f));
            }
        } else if constexpr (std::is_same_v<T, ipv4_header>) {
            switch (lay.proto) {
            case ipv4_header_base::ICMP:
                return handle<icmp_packet>(it, std::move(f));
            case ipv4_header_base::TCP:
                return handle<tcp_header>(it, std::move(f));
            case ipv4_header_base::UDP:
                return handle<udp_header>(it, std::move(f));
            default:
                return handle<blob>(it, std::move(f));
            }
        } else if constexpr (std::is_same_v<T, ipv6_header>) {
            switch (lay.next_header) {
            case ipv6_header::TCP:
                return handle<tcp_header>(it, std::move(f));
            case ipv6_header::UDP:
                return handle<udp_header>(it, std::move(f));
            default:
                return handle<blob>(it, std::move(f));
            }
        } else if constexpr (std::is_same_v<T, arp_packet>) {
            ;
        } else if constexpr (std::is_same_v<T, icmp_packet>) {
            ;
        } else if constexpr (std::is_same_v<T, udp_header>) {
            if (lay.is_dns()) {
                handle<dns_packet>(it, std::move(f));
            } else {
                handle<blob>(it, std::move(f));
            }
        } else if constexpr (std::is_same_v<T, tcp_header>) {
            if (lay.is_dns()) {
                handle<dns_packet>(it, std::move(f));
            } else {
                handle<blob>(it, std::move(f));
            }
        } else if constexpr (std::is_same_v<T, dns_packet>) {
            ;
        } else {
            static_assert(std::is_same_v<T, blob>);
            ;
        }
    }

public:
    static packet parse_packet(const uint8_t* begin, const uint8_t* end);

private:
    static void parse_datalink(const uint8_t* begin, const uint8_t* end, packet& pkt);

    template<typename T>
    static void parse_network(const uint8_t* begin, const uint8_t* end, packet& pkt) = delete;

    template<typename T>
    static void parse_transport(const uint8_t* begin, const uint8_t* end, packet& pkt) = delete;

    template<typename T>
    static void parse_application(const uint8_t* begin, const uint8_t* end, packet& pkt) = delete;

    static void parse_unknown(const uint8_t* begin, const uint8_t* end, packet& pkt);

public:
    friend QDataStream& operator<<(QDataStream& ds, const packet& pkt);
    friend QDataStream& operator>>(QDataStream& ds, packet& pkt);
};

//

struct pack {
    QDateTime time;
    std::vector<uint8_t> raw;
    packet parsed;

    QString time_str() const { return time.toString("MM/dd hh:mm:ss.zzz"); }
    QString raw_str() const {
        std::vector<char> tmpbuf(raw.size() * 5, '\0');
        uint offset = 0;
        for (size_t i = 0; i < raw.size(); i++) {
            offset += sprintf(tmpbuf.data() + offset, "%02hhx ", raw[i]);
            if ((i + 1) % 16 == 0)
                tmpbuf[offset++] = '\n';
            else if ((i + 1) % 8 == 0)
                offset += sprintf(tmpbuf.data() + offset, "  ");
        }
        return QString::fromLatin1(tmpbuf.data(), offset);
    }
    QString raw_len() const {
        return QString::number(raw.size());
    }
};

//

QDataStream& operator<<(QDataStream& ds, const packet& pkt);
QDataStream& operator>>(QDataStream& ds, packet& pkt);

QDataStream& operator<<(QDataStream& ds, const pack& pkt);
QDataStream& operator>>(QDataStream& ds, pack& pkt);

//

template<>
void packet::parse_network<ipv6_header>(const uint8_t* begin, const uint8_t* end, packet& pkt);

template<>
void packet::parse_network<ipv4_header>(const uint8_t* begin, const uint8_t* end, packet& pkt);

template<>
void packet::parse_network<arp_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt);

template<>
void packet::parse_transport<tcp_header>(const uint8_t* begin, const uint8_t* end, packet& pkt);

template<>
void packet::parse_transport<udp_header>(const uint8_t* begin, const uint8_t* end, packet& pkt);

template<>
void packet::parse_transport<icmp_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt);

template<>
void packet::parse_application<dns_packet>(const uint8_t* begin, const uint8_t* end, packet& pkt);

//
