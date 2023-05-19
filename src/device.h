#pragma once

#include "SafeQueue.h"
#include "packet.h"
#include <QDateTime>
#include <QString>
#include <pcap.h>
#include <thread>
//
// 使用例见最后

const QString DEFAULT_FILENAME = "./cap";

class device {
private:
    pcap_t* src;
    pcap_dumper_t* file;
    u_int netmask;
    bpf_program fcode;
    std::atomic_bool stop_flag = false;
    std::thread thread;
    SafeQueue<pack> queue;

public:
    device(const char* name, u_int netmask);

    device(device&& x);

    device(const device&) = delete;
    device& operator=(const device&) = delete;
    device& operator=(device&&) = delete;

    ~device();

private:
    auto get_packet() -> std::tuple<const pcap_pkthdr*, const u_char*>;

public:
    void stop();

    //失败则抛异常
    void set_filter(const std::string& filter);

    //不会阻塞，可能失败，失败时vec.empty() == true
    std::optional<pack> try_get();

    std::vector<pack> get_all();

    void start_capture();
};

class device_list {
private:
    pcap_if_t* header;
    uint sz;

public:
    device_list();

    device_list(device_list&& x);

    device_list(const device_list&) = delete;
    device_list& operator=(const device_list&) = delete;
    device_list& operator=(device_list&& x) = delete;

    ~device_list();

public:
    bool is_empty() const;

    uint size() const;

    //先做一个这个东西，有需要再做个完善的遍历访问功能
    std::vector<QString> to_strings() const;

    //i是索引，从0开始
    device open(uint i) const;
};

device open_file(const QString& file_name);
