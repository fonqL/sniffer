#include "handle_packet.h"
#include "parse.h"
#include <stdexcept>
//

device::device(const char* name, u_int netmask)
    : netmask(netmask) {
    char errbuf[PCAP_ERRBUF_SIZE];
    src = pcap_open(name,
                    65536,
                    PCAP_OPENFLAG_PROMISCUOUS,
                    1000,
                    nullptr,
                    errbuf);
    if (src == nullptr) throw std::runtime_error{errbuf};

    if (pcap_datalink(src) != DLT_EN10MB)
        pcap_close(src), throw std::runtime_error{"only for Ethernet networks."};
    const auto& tmp = DEFAULT_FILENAME.toLocal8Bit();
    file = pcap_dump_open(src, tmp.data());
    if (file == nullptr) pcap_close(src), throw std::runtime_error{"pcap_dump_open"};
}

device::device(device&& x)
    : src(x.src),
      file(x.file),
      netmask(x.netmask),
      fcode(x.fcode),
      thread(std::move(x.thread)) {
    stop_flag.store(x.stop_flag.load(std::memory_order_relaxed), std::memory_order_relaxed);
    x.src = nullptr, x.file = nullptr;
}

device::~device() {
    if (src == nullptr)
        return;
    if (thread.joinable())
        stop();
    pcap_dump_close(file);
    pcap_close(src);
}

std::tuple<const pcap_pkthdr*, const u_char*>
device::get_packet() {
    while (!stop_flag.load(std::memory_order_relaxed)) {
        pcap_pkthdr* header;
        const u_char* data;
        int e = pcap_next_ex(src, &header, &data);
        if (e < 0) break;
        if (e == 0) continue;
        pcap_dump((u_char*)file, header, data);
        return {header, data};
    }
    return {nullptr, nullptr};
}

void device::stop() {
    if (!thread.joinable())
        return;
    stop_flag.store(true, std::memory_order_relaxed);
    thread.join();
}

void device::set_filter(const std::string& filter) {
    if (filter.size() >= PCAP_BUF_SIZE) throw std::overflow_error{"filter string too long"};

    int e = pcap_compile(src, &fcode, filter.data(), 1, netmask);
    if (e < 0) throw std::runtime_error{"capture filter syntax error"};
    e = pcap_setfilter(src, &fcode);
    if (e < 0) throw std::runtime_error{"pcap_setfilter"};
}

std::vector<std::any> device::try_get() {
    return queue.tryPop().value_or(std::vector<std::any>{});
}

std::vector<std::vector<std::any>> device::get_all() {
    return queue.popAll();
}

void device::start_capture() {
    thread = std::thread([this]() {
        while (!stop_flag.load(std::memory_order_relaxed)) {
            auto [header, data] = get_packet();
            if (header == nullptr || data == nullptr) break;
            if (header->caplen != header->len || header->caplen == 0) continue;
            std::vector<std::any> res;
            res.push_back(simple_info{
                QDateTime::fromSecsSinceEpoch(header->ts.tv_sec)
                    + std::chrono::milliseconds{header->ts.tv_usec / 1000},
                { data,       data + header->len}
            });
            parse_datalink(data, data + header->len, res);
            if (res.size() > 1)
                queue.push(std::move(res));
        }
    });
}

device_list::device_list()
    : sz(0) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int e = pcap_findalldevs(&header, errbuf);
    if (e == PCAP_ERROR) throw std::runtime_error{errbuf};
    for (auto* dev = header; dev != nullptr; dev = dev->next) {
        ++sz;
    }
}

bool device_list::is_empty() const {
    return header == nullptr;
}

uint device_list::size() const {
    return sz;
}

device device_list::open(uint i) const {
    pcap_if_t* dev;
    for (dev = header; i > 0; --i) {
        dev = dev->next;
    }
    u_int netmask = dev->addresses != nullptr
                        ? ((sockaddr_in*)(dev->addresses->netmask))->sin_addr.S_un.S_addr
                        : 0xffffff; //fallback: C类地址
    return {dev->name, netmask};
}

std::vector<QString> device_list::to_strings() const {
    std::vector<QString> ret;
    for (auto* dev = header; dev != nullptr; dev = dev->next) {
        ret.push_back(
            QString::asprintf("%s: <%s>",
                              dev->description ? dev->description //
                                               : "Unknown",
                              dev->name));
    }
    return ret;
}

device_list::~device_list() {
    if (header != nullptr)
        pcap_freealldevs(header);
}

device_list::device_list(device_list&& x)
    : header(x.header), sz(x.sz) {
    x.header = nullptr;
}

device open_file(const QString& file_name) {
    if (file_name.size() >= PCAP_BUF_SIZE) throw std::overflow_error("filename too long");

    char ret_name[PCAP_BUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    const QByteArray& arg_name = file_name.toLocal8Bit();

    int e = pcap_createsrcstr(ret_name, PCAP_SRC_FILE, nullptr, nullptr, arg_name.data(), errbuf);
    if (e != 0) throw std::runtime_error{errbuf};

    return {ret_name, 0xffffff};
}
