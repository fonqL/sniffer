#include "parse.h"
#include <QString>
#include <any>
#include <pcap.h>
#include <stdexcept>
#include <string_view>
#include <vector>

static constexpr std::string_view DEFAULT_FILENAME = "./cap";

class pcap_wrapper {
private:
    pcap_t* src;
    pcap_dumper_t* file;
    u_int netmask;
    bpf_program fcode;

public:
    pcap_wrapper(const char* name, u_int netmask)
        : netmask(netmask) {
        char errbuf[PCAP_ERRBUF_SIZE];
        src = pcap_open(name,
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

private:
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

public:
    bool is_empty() const {
        return src == nullptr;
    }

    //返回语法检查结果。正确为true，错误为false。不许忽视结果
    [[nodiscard]] bool
    set_filter(std::string_view filter) {
        if (filter.size() >= PCAP_BUF_SIZE) throw std::overflow_error{"filter string too long"};

        char buf[PCAP_BUF_SIZE] = {0};
        filter.copy(buf, filter.size()); //copyto buf

        //todo 假设compile是无状态的。。错误后对src无影响。。待测试。。
        int e = pcap_compile(src, &fcode, buf, 1, netmask);
        if (e < 0)
            return false;
        e = pcap_setfilter(src, &fcode); //这里错误就没救了
        if (e < 0) throw std::runtime_error{"pcap_setfilter"};
        return true;
    }

    void capture() { //qthread
        while (true) {
            auto [header, data] = get_packet();
            char timestr[16];
            time_t local_tv_sec = header->ts.tv_sec;
            tm ltime;
            localtime_s(&ltime, &local_tv_sec);
            strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

            printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);

            std::vector<std::any> headers;
            parse_datalink(data, data + header->len, headers);
        }
    }
};

class device_list {
private:
    pcap_if_t* header;

public:
    device_list() {
        char errbuf[PCAP_ERRBUF_SIZE];
        int e = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &header, errbuf);
        if (e == PCAP_ERROR) throw std::runtime_error{errbuf};
    }

    device_list(device_list&& x)
        : header(x.header) {
        x.header = nullptr;
    }

    device_list(const device_list&) = delete;
    device_list& operator=(const device_list&) = delete;
    device_list& operator=(device_list&& x) = delete;

    ~device_list() {
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
                QString("%1 (%2)").arg(dev->description ? dev->description
                                                        : "No description")
                    .arg(dev->name));
        }
        return ret;
    }

    //i是索引，从0开始
    pcap_wrapper open(uint i) {
        pcap_if_t* dev;
        for (dev = header; i > 0; --i) {
            dev = dev->next;
        }
        u_int netmask = dev->addresses != nullptr
                            ? ((sockaddr_in*)(dev->addresses->netmask))->sin_addr.S_un.S_addr
                            : 0xffffff; //fallback: C类地址
        return {dev->name, netmask};
        //todo 这里需要test，wrapper和list之间能不能靠复制摆脱生命周期联系
    }
};

inline pcap_wrapper open_file(std::string_view file_name) {
    if (file_name.size() >= PCAP_BUF_SIZE) throw std::overflow_error("filename too long");

    char source_name[PCAP_BUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    char raw_name[PCAP_BUF_SIZE] = {0};
    file_name.copy(raw_name, file_name.size());

    int e = pcap_createsrcstr(source_name, PCAP_SRC_FILE, nullptr, nullptr, raw_name, errbuf);
    if (e != 0) throw std::runtime_error{"pcap_createsrcstr"};

    return {source_name, 0xffffff};
}
