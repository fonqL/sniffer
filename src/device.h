#pragma once

#include "SafeQueue.h"
#include "packet.h"
#include <QString>
#include <pcap.h>
#include <thread>
//
// 使用例见最后

const QString DEFAULT_FILENAME = "./cap";

inline void pcap_assert(bool invar, const char* msg) {
    [[unlikely]] if (!invar)
        throw std::runtime_error(msg);
}

// e==0 means success.
inline void pcap_assert(int e, const char* msg) {
    pcap_assert(e == 0, msg);
}

inline void pcap_assert(void* p, const char* msg) {
    pcap_assert(p != nullptr, msg);
}

inline void pcap_assert(int e) {
    [[unlikely]] if (!(e == 0))
        throw std::runtime_error(pcap_statustostr(e));
}

class device {
    static constexpr size_t DEVICE_THREAD_PLUS = 2;

private:
    pcap_t* src;
    pcap_dumper_t* file;
    u_int netmask;
    bpf_program fcode;
    std::atomic_bool stop_flag = false;
    std::vector<std::thread> threads;
    SafeQueue<pack> queue;
    std::mutex mtx;

public:
    device(const char* name, u_int netmask);

    device(device&& x) noexcept;

    device(const device&) = delete;
    device& operator=(const device&) = delete;
    device& operator=(device&&) = delete;

    ~device();

private:
    auto get_packet() -> std::tuple<const pcap_pkthdr*, const u_char*>;

    void _pcap_assert(int e) {
        [[unlikely]] if (!(e == 0))
            throw std::runtime_error(pcap_geterr(src));
    }

public:
    void stop();

    //失败则抛异常
    void set_filter(const std::string& filter);

    //不会阻塞，可能失败，失败时vec.empty() == true
    std::optional<pack> try_get();

    std::vector<pack> get_some(uint n);

    void start_capture();
};

class device_list {
private:
    pcap_if_t* header;
    uint sz;

public:
    device_list();

    device_list(device_list&& x) noexcept;

    device_list(const device_list&) = delete;
    device_list& operator=(const device_list&) = delete;
    device_list& operator=(device_list&& x) = delete;

    ~device_list();

public:
    bool empty() const noexcept;

    uint size() const noexcept;

    //先做一个这个东西，有需要再做个完善的遍历访问功能
    std::vector<QString> to_strings() const;

    //i是索引，从0开始
    device open(uint i) const;
};

device open_file(const QString& file_name);
