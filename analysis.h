#include "handle_packet.h"

//用于分析的类，直接用packet创建，然后用其成员变量
class analysis{
    public:
    QString time;
    QString header;
    QString srcMac;
    QString desMac;
    analysis(std::vector<std::any> packet){
        simple_info info = std::any_cast<simple_info>(packet[0]);
        eth_header eth = std::any_cast<eth_header>(packet[1]);

        char *buf = (char *)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", eth.src[0], eth.src[1], 
        eth.src[2], eth.src[3], eth.src[4], eth.src[5]);
        srcMac = QString(QLatin1String(buf));
        buf = (char *)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", eth.dst[0], eth.dst[1], 
        eth.dst[2], eth.dst[3], eth.dst[4], eth.dst[5]);
        desMac = QString(QLatin1String(buf));

        time = info.t.toString("yyyy-MM-dd hh:mm:ss");
        if(typeid(eth.type)==typeid(eth_header::IPv4)){
            header = "IPv4";
        }
        else if(typeid(eth.type)==typeid(eth_header::ARP)){
            header = "ARP";
        }
        else if(typeid(eth.type)==typeid(eth_header::IPv6)){
            header = "IPv6";
        }
        else{
            header = "其他协议";
        }
    }
};