#include "pcap.h"
#include "protocol.h"
#include <QString>
#include <WinSock2.h>
#include <any>
#include <stdexcept>
#include <string_view>
#include <vector>

//
// 使用例：
// int main() try {
//     dev_list devices;
//     auto x = devices.to_strings();
//     for (uint i = 0; i < x.size(); ++i)
//         std::cout << i << ". " << x[i].toStdString() << '\n';
//     uint i;
//     std::cin >> i;
//     std::cout << i << '\n';
//     auto device = devices.open(i);
//     device.capture();
// } catch (std::exception& e) {
//     std::cout << e.what() << std::endl;
// }

static constexpr std::string_view DEFAULT_FILENAME = "./cap";

class pcap_wrapper { //todo支持文件类型
private:
    pcap_if_t info;
    pcap_t* src;
    pcap_dumper_t* file;
    bpf_program fcode;

public:
    pcap_wrapper(pcap_if_t* dev) {
        memcpy(&info, dev, sizeof(*dev));

        char errbuf[PCAP_ERRBUF_SIZE];
        src = pcap_open(dev->name,
                        65536,
                        PCAP_OPENFLAG_PROMISCUOUS,
                        1000,
                        nullptr,
                        errbuf);
        if (src == nullptr) throw std::runtime_error{errbuf};

        if (pcap_datalink(src) != DLT_EN10MB) pcap_close(src), throw std::runtime_error{"only for Ethernet networks."};

        file = pcap_dump_open(src, DEFAULT_FILENAME.data());
        if (file == nullptr) pcap_close(src), throw std::runtime_error{"pcap_dump_open"};
    }

    pcap_wrapper(pcap_wrapper&& x)
        : src(x.src), file(x.file) {
        x.src = nullptr, x.file = nullptr;
    }

    pcap_wrapper(const pcap_wrapper&) = delete;
    pcap_wrapper& operator=(const pcap_wrapper&) = delete;
    pcap_wrapper& operator=(pcap_wrapper&&) = delete;

    ~pcap_wrapper() {
        if (src != nullptr)
            pcap_dump_close(file), pcap_close(src);
    }

public:
    std::tuple<const pcap_pkthdr*, const u_char*> get_packet() {
        while (true) {
            pcap_pkthdr* header;
            const u_char* data;
            int e = pcap_next_ex(src, &header, &data);
            if (e < 0) throw std::runtime_error{"pcap_next_ex"};
            if (e == 0) continue;
            pcap_dump((u_char*)file, header, data);
            return {header, data};
        }
    }

    //返回语法检查结果。正确为true，错误为false
    bool set_filter(std::string_view filter) {
        //todo 假设compile是无状态的。。错误后对src无影响。。待测试。。
        int e = pcap_compile(src, &fcode, filter.data(), 1,
                             info.addresses != nullptr
                                 ? ((sockaddr_in*)(info.addresses->netmask))->sin_addr.S_un.S_addr
                                 : 0xffffff); // fallback: C类地址
        if (e < 0)
            return false;
        e = pcap_setfilter(src, &fcode); //这里错误就没救了
        if (e < 0) throw std::runtime_error{"pcap_setfilter"};
        return true;
    }

    void capture() {
        while (true) {
            auto [header, data] = get_packet();
            char timestr[16];
            time_t local_tv_sec = header->ts.tv_sec;
            tm ltime;
            localtime_s(&ltime, &local_tv_sec);
            strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

            printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
        }
    }
};

class dev_list {
private:
    pcap_if_t* header;

public:
    dev_list() {
        char errbuf[PCAP_ERRBUF_SIZE];
        int e = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &header, errbuf);
        if (e == PCAP_ERROR) throw std::runtime_error{errbuf};
    }

    dev_list(dev_list&& x)
        : header(x.header) {
        x.header = nullptr;
    }

    dev_list(const dev_list&) = delete;
    dev_list& operator=(const dev_list&) = delete;
    dev_list& operator=(dev_list&& x) = delete;

    ~dev_list() {
        if (header != nullptr)
            pcap_freealldevs(header);
    }

public:
    bool is_empty() const {
        return header == nullptr;
    }

    //先做一个这个东西，有需要再做个完善的遍历访问功能
    std::vector<QString> to_strings() {
        std::vector<QString> ret;
        for (auto* dev = header; dev != nullptr; dev = dev->next) {
            ret.push_back(
                QString("%1 (%2)").arg(dev->name).arg(dev->description ? dev->description
                                                                       : "No description"));
        }
        return ret;
    }

    //i是索引，从0开始
    pcap_wrapper open(uint i) {
        pcap_if_t* dev;
        for (dev = header; i > 0; --i) {
            dev = dev->next;
        }
        return {dev}; //todo 这里需要test
    }
};
