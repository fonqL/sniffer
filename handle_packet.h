#pragma once

#include "SafeQueue.h"
#include <QDateTime>
#include <QString>
#include <any>
#include <pcap.h>
#include <thread>
//
// 使用例见最后

const QString DEFAULT_FILENAME = "./cap";

struct simple_info {
    QDateTime t;
    std::vector<uint8_t> raw_data;
};

class device {
private:
    pcap_t* src;
    pcap_dumper_t* file;
    u_int netmask;
    bpf_program fcode;
    std::atomic_bool stop_flag = false;
    std::thread thread;
    SafeQueue<std::vector<std::any>> queue;

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

    //返回语法检查结果。正确为true，错误为false。不许忽视结果
    [[nodiscard]] bool
    set_filter(std::string filter);

    //不会阻塞，可能失败，失败时vec.empty() == true
    std::vector<std::any> try_get();

    std::vector<std::vector<std::any>> get_all();

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

// 使用例
// #include "handle_packet.h"
// #include <iostream>
// int main() {
//     device_list devs;
//     std::vector<QString> infos = devs.to_strings();
//     for (uint i = 0; i < infos.size(); ++i)
//         qDebug() << i << ' ' << infos[i] << '\n';
//     //要把CMakeLists.txt换成CMakeLists-cmd.txt 或在qt里运行才有命令行输出功能
//
//     uint index;
//     std::cin >> index;
//     device dev = devs.open(index);
//     if (dev.set_filter("") == false) //可选步骤，字符串也可为空
//         return -1;
//
//     dev.start_capture(); //启动抓包，自动起了一个线程。不会在这阻塞
//     while (true) {
//         std::vector<std::any> packet = device.try_get();
//
//         //处理info...
//         simple_info info = std::any_cast<simple_info>(packet[0]);
//
//         //处理以太帧...
//         eth_header eth = std::any_cast<eth_header>(packet[1]); //第一项肯定是以太头
//
//         //处理网络层...
//         if (packet[2].type() == typeid(ipv4_header)) {
//             ...
//         }else if...

//     }
//     dev.stop(); //在这里会阻塞，等待停止
// }
