#pragma once
#include "protocol.h"
#include <QDateTime>
#include <cassert>
#include <stdexcept>
#include <type_traits>
#include <typeindex>
#include <vector>

class QDataStream;

// 异质容器
class packet {
private:
    template<class T>
    using Alloc = std::allocator<T>;

    using ltype = std::pair<std::type_index, size_t>;

    // ！！绝对不能写赋值和析构！！就是要这样调裸的函数！！
    struct _impl : private Alloc<uint8_t> {
        uint8_t* begin = nullptr;
        uint8_t* end = nullptr;

        void deallocate() {
            Alloc<uint8_t>::deallocate(begin, end - begin);
        }

        void allocate(size_t size) {
            begin = Alloc<uint8_t>::allocate(size);
            end = begin + size;
        }
    };

public:
    packet() = default;
    packet(const packet&) = delete;
    packet(packet&& x) noexcept
        : impl(x.impl), mid(x.mid), l_end(x.l_end), r_end(x.r_end) {
        x.impl.begin = nullptr;
    }
    packet& operator=(const packet&) = delete;
    packet& operator=(packet&& x) noexcept {
        this->~packet();
        impl = x.impl;
        mid = x.mid;
        l_end = x.l_end;
        r_end = x.r_end;
        x.impl.begin = nullptr;
        return *this;
    };
    ~packet() {
        if (impl.begin != nullptr)
            impl.deallocate();
    }

public:
    struct iterator {
    private:
        ltype* it;
        uint8_t* begin;

    public:
        iterator() noexcept : it(nullptr), begin(nullptr) {}
        iterator(ltype* p, uint8_t* mid) noexcept : it(p), begin(mid) {}

        bool operator!=(const iterator& rhs) const noexcept {
            return it != rhs.it || begin != rhs.begin;
        }

        std::pair<std::type_index, void*> operator*() const noexcept {
            return {it->first, begin + it->second};
        }

        iterator& operator++() noexcept {
            ++it;
            return *this;
        }
    };

public:
    iterator begin() noexcept {
        return {reinterpret_cast<ltype*>(l_end), mid};
    }
    iterator end() noexcept {
        return {reinterpret_cast<ltype*>(mid), mid};
    }
    size_t size() const noexcept {
        return (mid - l_end) / sizeof(ltype);
    }
    bool empty() const noexcept {
        return l_end == mid;
    }

private:
    // 扩容
    void expand(size_t atlease_r) {
        size_t size = r_end - l_end;
        size_t lsize = mid - l_end;
        size_t rsize = r_end - mid;

        _impl newimpl;
        newimpl.allocate(2 * (std::max(lsize, sizeof(ltype)) + std::max(rsize, atlease_r)));

        mid = newimpl.begin + 2 * std::max(lsize, sizeof(ltype));

        uint8_t* old_l = l_end;
        l_end = mid - lsize;
        r_end = mid + rsize;

        memcpy(l_end, old_l, size);
        impl.deallocate();
        impl = newimpl;
    }

    void ensure_capacity(size_t atlease_r) {
        if (l_end - sizeof(ltype) < impl.begin
            || impl.end <= r_end + atlease_r) {
            expand(atlease_r);
        }
    }

    template<typename T>
    auto add_impl(T&& a) -> std::remove_reference_t<T>& {
        l_end -= sizeof(ltype);
        *reinterpret_cast<ltype*>(l_end) = {typeid(T), r_end - mid};

        //
        auto* ret = reinterpret_cast<std::remove_reference_t<T>*>(r_end);

        memcpy(r_end, reinterpret_cast<uint8_t*>(&a), sizeof(T));
        r_end += sizeof(T);

        return *ret;
    }

public:
    // 添加定长头
    template<typename T>
    auto add(T&& a) -> std::remove_reference_t<T>& {
        static_assert(std::is_trivial_v<T>);

        ensure_capacity(sizeof(T));

        return add_impl(std::forward(a));
    }

    // 添加定长头+最后的变长数据
    template<typename T>
    auto add(T&& a, const uint8_t* const begin, const uint8_t* const end) -> std::remove_reference_t<T>& {
        static_assert(std::is_trivial_v<T>);
        size_t append_len = end - begin;

        ensure_capacity(sizeof(T) + append_len);
        auto* ret = add_impl(std::forward(a));

        memcpy(r_end, begin, append_len);
        r_end += append_len;

        return *ret;
    }

    // 获得定长头（变长数据靠最后的零长数组获得
    template<typename T>
    const T* get() const noexcept {
        static_assert(std::is_trivial_v<T>);

        auto* it = reinterpret_cast<const ltype*>(l_end);
        auto* end = reinterpret_cast<const ltype*>(mid);
        for (; it < end; ++it) {
            if (it->first == typeid(T)) {
                return reinterpret_cast<const T*>(mid + it->second);
            }
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

private:
    _impl impl;
    uint8_t* mid = nullptr;
    uint8_t* l_end = nullptr;
    uint8_t* r_end = nullptr;

    // 拓展，实现高级协议(如http时)还是需要靠vector any
    // std::vector<std::any> advanced_proto;
};

//

QDataStream& operator<<(QDataStream& ds, const packet& pkt);
QDataStream& operator>>(QDataStream& ds, packet& pkt);

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

struct pack {
    QDateTime time;
    std::vector<uint8_t> raw;
    packet parsed;
};

QDataStream& operator<<(QDataStream& ds, const pack& pkt);
QDataStream& operator>>(QDataStream& ds, pack& pkt);
