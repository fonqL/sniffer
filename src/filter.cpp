// #include "mainwindow.h"
// #include <regex>
// #include <string>

// /*----------显示过滤器的一些声明&函数定义--------*/
// std::regex _empty(" ");   //去除空格
// std::regex _and(" and "); //关键字符
// std::regex _or(" or ");
// std::regex _bigger(">"); //运算符
// std::regex _smaller("<");
// std::regex _big_or_eq(">=");
// std::regex _small_or_eq("<=");
// std::regex _equal("==");
// std::regex _not_eq("!=");

// /*-----------------------------------------------------------------*/
// /*
//     --ip、port仅支持==运算
//     --各种包的len支持>、<=等运算符
//     --多条件只允许只含有and/or,例如：
//         tcp and dns and ip=0.0.0.0 √
//         udp or tcp or !ipv4        √
//         tcp and ipv4 or !dns       ×
//         (真要搞这个太复杂了，懒得搞了)
//     --值匹配：
//         ip|ip.dst|ip.src|port
//         tcp.port|tcp.dst|tcp.src
//         udp.port|udp.dst|udp.src
//         len|ipv4.len|.....|tcp.len
// */
// //判断是不是一个合法的过滤语句
// bool MainWindow::is_a_sentence(const QString& fil) {
//     std::string filter = fil.toStdString();
//     if (std::regex_match(filter, std::regex(" *"))) //空语句
//         return false;
//     else if (std::regex_search(filter, _and)) //and语句
//     {
//         std::vector<std::string> filt = split_and(filter);
//         for (int i = 0; i < filt.size(); i++) {
//             if (is_a_filter(filt[i]) == false)
//                 return false;
//         }
//         return true;
//     } else if (std::regex_search(filter, _or)) //or语句
//     {
//         std::vector<std::string> filt = split_or(filter);
//         for (uint i = 0; i < filt.size(); i++) {
//             if (is_a_filter(filt[i]) == false)
//                 return false;
//         }
//         return true;
//     } else //单子句
//     {
//         return is_a_filter(filter);
//     }
//     //false报错：请输入正确的过滤语句
// }

// //判断子句有没有语法问题
// bool MainWindow::is_a_filter(const std::string& filter) {
//     //端口范围：0-65535，超出会报错
//     //ip范围：0.0.0.0--255.255.255.255
//     if (std::regex_match(filter, std::regex(" *arp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *tcp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *udp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *icmp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *dns *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *ipv4 *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *ipv6 *", std::regex::icase)))
//         return true;

//     else if (std::regex_match(filter, std::regex("^ *ip\\.dst *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ip\\.src *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ip *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;

//     //长度==
//     else if (std::regex_match(filter, std::regex("^ *len *== *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *arp\\.len *== *[1-9][0-9]* *$"))) //arp包长度，下面同理
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *== *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *== *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.len *== *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.len *== *[1-9][0-9]* *$")))
//         return true;

//     //长度>=
//     else if (std::regex_match(filter, std::regex("^ *len *>= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *arp\\.len *>= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *>= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *>= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.len *>= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.len *>= *[1-9][0-9]* *$")))
//         return true;

//     //长度<=
//     else if (std::regex_match(filter, std::regex("^ *len *<= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *arp\\.len *<= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *<= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *<= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.len *<= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.len *<= *[1-9][0-9]* *$")))
//         return true;

//     //长度>
//     else if (std::regex_match(filter, std::regex("^ *len *> *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *arp\\.len *> *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *> *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *> *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.len *> *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.len *> *[1-9][0-9]* *$")))
//         return true;

//     //长度<
//     else if (std::regex_match(filter, std::regex("^ *len *< *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *arp\\.len *< *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *< *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *< *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.len *< *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.len *< *[1-9][0-9]* *$")))
//         return true;

//     //值不等,例如：ip != 0.0.0.0
//     else if (std::regex_match(filter, std::regex("^ *ip\\.dst *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ip\\.src *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ip *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *len *!= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *arp\\.len *!= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *!= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *!= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.len *!= *[1-9][0-9]* *$")))
//         return true;
//     else if (std::regex_match(filter, std::regex("^ *udp\\.len *!= *[1-9][0-9]* *$")))
//         return true;

//     //不看某协议,例如： !dns
//     if (std::regex_match(filter, std::regex(" *!arp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *!tcp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *!udp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *!icmp *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *!dns *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *!ipv4 *", std::regex::icase)))
//         return true;
//     else if (std::regex_match(filter, std::regex(" *!ipv6 *", std::regex::icase)))
//         return true;

//     else
//         return false;
// }

// //过滤抓到的包,结果返回的出口
// std::vector<int> MainWindow::catched_filter(const std::string& s) {
//     if (std::regex_search(s, _and)) //and语句
//     {
//         std::vector<std::vector<int>> temp;
//         std::vector<std::string> filt = split_and(s);
//         //分析子句，将结果存入temp
//         for (int i = 0; i < filt.size(); i++) {
//             temp.push_back(analyse_filter(filt[i]));
//         }
//         return complex_and(temp);
//     } else if (std::regex_search(s, _or)) //or语句
//     {
//         std::vector<std::vector<int>> temp;
//         std::vector<std::string> filt = split_or(s);
//         for (int i = 0; i < filt.size(); i++) {
//             temp.push_back(analyse_filter(filt[i]));
//         }
//         return complex_or(temp);
//     }
//     //单子句直接丢进analyse_filter()就能得出结果了
//     else
//         return analyse_filter(s);
// }

// //分析子句,返回一个索引容器
// std::vector<int> MainWindow::analyse_filter(const std::string& filter) {
//     //预处理，将运算符后面的值提取出来存入set_data
//     std::vector<std::string> temp_data;
//     std::string set_data;
//     std::vector<int> results;
//     if ((std::regex_search(filter, _equal))) // ==
//     {
//         std::sregex_token_iterator beg(filter.begin(), filter.end(), _equal, -1);
//         std::sregex_token_iterator end;
//         for (; beg != end; beg++) {
//             temp_data.push_back(beg->str());
//         }
//         if (temp_data.size() == 2) {
//             set_data = std::regex_replace(temp_data[1], _empty, "");
//         }
//     } else if ((std::regex_search(filter, _big_or_eq))) // >=
//     {
//         std::sregex_token_iterator beg(filter.begin(), filter.end(), _big_or_eq, -1);
//         std::sregex_token_iterator end;
//         for (; beg != end; beg++) {
//             temp_data.push_back(beg->str());
//         }
//         if (temp_data.size() == 2) {
//             set_data = std::regex_replace(temp_data[1], _empty, "");
//         }
//     } else if ((std::regex_search(filter, _small_or_eq))) // <=
//     {
//         std::sregex_token_iterator beg(filter.begin(), filter.end(), _small_or_eq, -1);
//         std::sregex_token_iterator end;
//         for (; beg != end; beg++) {
//             temp_data.push_back(beg->str());
//         }
//         if (temp_data.size() == 2) {
//             set_data = std::regex_replace(temp_data[1], _empty, "");
//         }
//     } else if ((std::regex_search(filter, _smaller))) // <
//     {
//         std::sregex_token_iterator beg(filter.begin(), filter.end(), _smaller, -1);
//         std::sregex_token_iterator end;
//         for (; beg != end; beg++) {
//             temp_data.push_back(beg->str());
//         }
//         if (temp_data.size() == 2) {
//             set_data = std::regex_replace(temp_data[1], _empty, "");
//         }
//     } else if ((std::regex_search(filter, _bigger))) // >
//     {
//         std::sregex_token_iterator beg(filter.begin(), filter.end(), _bigger, -1);
//         std::sregex_token_iterator end;
//         for (; beg != end; beg++) {
//             temp_data.push_back(beg->str());
//         }
//         if (temp_data.size() == 2) {
//             set_data = std::regex_replace(temp_data[1], _empty, "");
//         }
//     } else if ((std::regex_search(filter, _not_eq))) {
//         std::sregex_token_iterator beg(filter.begin(), filter.end(), _not_eq, -1);
//         std::sregex_token_iterator end;
//         for (; beg != end; beg++) {
//             temp_data.push_back(beg->str());
//         }
//         if (temp_data.size() == 2) {
//             set_data = std::regex_replace(temp_data[1], _empty, "");
//         }
//     }

//     //按协议
//     if (std::regex_match(filter, std::regex(" *arp *", std::regex::icase))) //arp协议
//         return this->count.arp_c;
//     else if (std::regex_match(filter, std::regex(" *tcp *", std::regex::icase)))
//         return this->count.tcp_c;
//     else if (std::regex_match(filter, std::regex(" *udp *", std::regex::icase)))
//         return this->count.udp_c;
//     else if (regex_match(filter, std::regex(" *icmp *", std::regex::icase)))
//         return this->count.icmp_c;
//     else if (regex_match(filter, std::regex(" *dns *", std::regex::icase)))
//         return this->count.dns_c;
//     else if (regex_match(filter, std::regex(" *ipv4 *", std::regex::icase)))
//         return this->count.ipv4_c;
//     else if (std::regex_match(filter, std::regex(" *ipv6 *", std::regex::icase)))
//         return this->count.ipv6_c; //下面是取反
//     else if (std::regex_match(filter, std::regex(" *!arp *", std::regex::icase)))
//         return fixed_result(this->count.arp_c);
//     else if (std::regex_match(filter, std::regex(" *!tcp *", std::regex::icase)))
//         return fixed_result(this->count.tcp_c);
//     else if (std::regex_match(filter, std::regex(" *!udp *", std::regex::icase)))
//         return fixed_result(this->count.udp_c);
//     else if (regex_match(filter, std::regex(" *!icmp *", std::regex::icase)))
//         return fixed_result(this->count.icmp_c);
//     else if (regex_match(filter, std::regex(" *!dns *", std::regex::icase)))
//         return fixed_result(this->count.dns_c);
//     else if (regex_match(filter, std::regex(" *!ipv4 *", std::regex::icase)))
//         return fixed_result(this->count.ipv4_c);
//     else if (std::regex_match(filter, std::regex(" *!ipv6 *", std::regex::icase)))
//         return fixed_result(this->count.ipv6_c);

//     //源、目的IP地址
//     else if (std::regex_match(filter, std::regex("^ *ip *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             std::string saved1 = std::regex_replace(aaa.srcIp.toStdString(), _empty, "");
//             std::string saved2 = std::regex_replace(aaa.desIp.toStdString(), _empty, "");
//             if ((saved1 == set_data) || (saved2 == set_data))
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //目的ip地址
//     else if (std::regex_match(filter, std::regex("^ *ip\\.dst *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             std::string saved = std::regex_replace(aaa.desIp.toStdString(), _empty, "");
//             if (saved == set_data)
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //源ip地址
//     else if (std::regex_match(filter, std::regex("^ *ip\\.src *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             std::string saved = std::regex_replace(aaa.srcIp.toStdString(), _empty, "");
//             if (saved == set_data)
//                 results.push_back(i);
//         }
//         return results;
//     }

//     //TCP目的端口
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.tcp.dst;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans == saved)
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //TCP源端口
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.tcp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans == saved)
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //TCP源、目的端口
//     else if (std::regex_match(filter, std::regex("^ *tcp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.tcp.dst;
//             uint16_t saved2 = aaa.tcp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans == saved1) || (trans == saved2))
//                 results.push_back(i);
//         }
//         return results;
//     }

//     //UDP目的端口
//     else if (std::regex_match(filter, std::regex("^ *udp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.udp.dst;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans == saved)
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //UDP源端口
//     else if (std::regex_match(filter, std::regex("^ *udp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.udp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans == saved)
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //UDP源、目的端口
//     else if (std::regex_match(filter, std::regex("^ *udp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.udp.dst;
//             uint16_t saved2 = aaa.udp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans == saved1) || (trans == saved2))
//                 results.push_back(i);
//         }
//         return results;
//     }

//     //所有端口
//     else if (std::regex_match(filter, std::regex("^ *port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.udp.dst;
//             uint16_t saved2 = aaa.udp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans == saved1) || (trans == saved2))
//                 results.push_back(i);
//         }
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.tcp.dst;
//             uint16_t saved2 = aaa.tcp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans == saved1) || (trans == saved2))
//                 results.push_back(i);
//         }
//         return results;
//     }

//     //长度限制
//     //长度==
//     else if (std::regex_match(filter, std::regex("^ *len *== *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved == trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *arp\\.len *== *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.arp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved == trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *== *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv4_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved == trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *== *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv6_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved == trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.len *== *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.tcp.header_len);
//             if (saved == trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.len *== *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.udp.len);
//             if (saved == trans)
//                 results.push_back(i);
//         }
//         return results;
//     }
//     //长度>=
//     else if (std::regex_match(filter, std::regex("^ *len *>= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved >= trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *arp\\.len *>= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.arp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved >= trans)
//                 results.push_back(count.arp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *>= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv4_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved >= trans)
//                 results.push_back(count.ipv4_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *>= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv6_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved >= trans)
//                 results.push_back(count.ipv6_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.len *>= *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.tcp.header_len);
//             if (saved >= trans)
//                 results.push_back(count.tcp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.len *>= *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.udp.len);
//             if (saved >= trans)
//                 results.push_back(count.udp_c[i]);
//         }
//         return results;
//     }
//     //长度<=
//     else if (std::regex_match(filter, std::regex("^ *len *<= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved <= trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *arp\\.len *<= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.arp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved <= trans)
//                 results.push_back(count.arp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *<= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv4_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved <= trans)
//                 results.push_back(count.ipv4_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *<= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv6_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved <= trans)
//                 results.push_back(count.ipv6_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.len *<= *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.tcp.header_len);
//             if (saved <= trans)
//                 results.push_back(count.tcp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.len *<= *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.udp.len);
//             if (saved <= trans)
//                 results.push_back(count.udp_c[i]);
//         }
//         return results;
//     }
//     //长度<
//     else if (std::regex_match(filter, std::regex("^ *len *< *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved < trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *arp\\.len *< *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.arp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved < trans)
//                 results.push_back(count.arp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *< *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv4_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved < trans)
//                 results.push_back(count.ipv4_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *< *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv6_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved < trans)
//                 results.push_back(count.ipv6_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.len *< *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.tcp.header_len);
//             if (saved < trans)
//                 results.push_back(count.tcp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.len *< *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.udp.len);
//             if (saved < trans)
//                 results.push_back(count.udp_c[i]);
//         }
//         return results;
//     }
//     //长度>
//     else if (std::regex_match(filter, std::regex("^ *len *> *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved > trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *arp\\.len *> *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.arp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved > trans)
//                 results.push_back(count.arp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *> *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv4_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved > trans)
//                 results.push_back(count.ipv4_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *> *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv6_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved > trans)
//                 results.push_back(count.ipv6_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.len *> *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.tcp.header_len);
//             if (saved > trans)
//                 results.push_back(count.tcp_c[i]);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.len *> *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.udp.len);
//             if (saved > trans)
//                 results.push_back(count.udp_c[i]);
//         }
//         return results;
//     }

//     //各种不等关系!=
//     else if (std::regex_match(filter, std::regex("^ *ip *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             std::string saved1 = std::regex_replace(aaa.srcIp.toStdString(), _empty, "");
//             std::string saved2 = std::regex_replace(aaa.desIp.toStdString(), _empty, "");
//             if ((saved1 != set_data) && (saved2 != set_data))
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ip\\.dst *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             std::string saved = std::regex_replace(aaa.desIp.toStdString(), _empty, "");
//             if (saved != set_data)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ip\\.src *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             std::string saved = std::regex_replace(aaa.srcIp.toStdString(), _empty, "");
//             if (saved != set_data)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.tcp.dst;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans != saved)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.tcp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans != saved)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.tcp.dst;
//             uint16_t saved2 = aaa.tcp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans != saved1) && (trans != saved2))
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.udp.dst;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans != saved)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved = aaa.udp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if (trans != saved)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.udp.dst;
//             uint16_t saved2 = aaa.udp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans != saved1) && (trans != saved2))
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$"))) {
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.udp.dst;
//             uint16_t saved2 = aaa.udp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans != saved1) && (trans != saved2))
//                 results.push_back(i);
//         }
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             uint16_t saved1 = aaa.tcp.dst;
//             uint16_t saved2 = aaa.tcp.src;
//             uint16_t trans = std::stoul(set_data); //把set_data 转成uint16_t
//             if ((trans != saved1) && (trans != saved2))
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *len *!= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->packets.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved != trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *arp\\.len *!= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.arp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved != trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *!= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv4_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved != trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *!= *[1-9][0-9]* *$"))) {
//         for (int i = 0; i < this->count.ipv6_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = aaa.len.toInt();
//             int trans = std::stoi(set_data.c_str());
//             if (saved != trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *tcp\\.len *!= *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.tcp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.tcp.header_len);
//             if (saved != trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else if (std::regex_match(filter, std::regex("^ *udp\\.len *!= *[1-9][0-9]* *$"))) {
//         int trans = std::stoi(set_data, 0, 10);
//         for (int i = 0; i < this->count.udp_c.size(); i++) {
//             analysis aaa(this->packets.at(i));
//             int saved = int(aaa.udp.len);
//             if (saved != trans)
//                 results.push_back(i);
//         }
//         return results;
//     } else {
//         //改一下，返回空vector
//         std::vector<int> not_found;
//         return not_found;
//     }
// }

// //分割and语句
// std::vector<std::string> MainWindow::split_and(const std::string& filter) {
//     std::vector<std::string> filt;
//     std::sregex_token_iterator beg(filter.begin(), filter.end(), _and, -1);
//     std::sregex_token_iterator end; //结束标志
//     for (; beg != end; beg++) {
//         filt.push_back(beg->str());
//     }
//     return filt;
// }

// //分割or语句
// std::vector<std::string> MainWindow::split_or(const std::string& filter) {
//     std::vector<std::string> fff;
//     std::sregex_token_iterator beg(filter.begin(), filter.end(), _or, -1);
//     std::sregex_token_iterator end; //结束标志
//     for (; beg != end; beg++) {
//         fff.push_back(beg->str());
//     }
//     return fff;
// }

// //求并集
// std::vector<int> MainWindow::complex_or(std::vector<std::vector<int>>& temp) {
//     std::vector<int> results;
//     std::vector<int> to_delete;

//     for (int i = 0; i < temp.size(); i++)
//         if (temp[i].size() == 0)
//             to_delete.push_back(i);
//     //删除空的索引组
//     if (to_delete.size() != 0) {
//         for (int i = 0; i < to_delete.size(); i++)
//             temp.push_back(temp[to_delete[i]]);
//     }
//     //如果temp还有东西，说明过滤出东西来了
//     //用第一个索引组初始化
//     if (temp.size() != 0) {
//         for (int i = 0; i < temp[0].size(); i++)
//             results.push_back(temp[0][i]);
//     } else return results; //返回一个空索引
//     //对temp中逐一判断：
//     //第i个索引组里的第j个元素 是否 在results中
//     for (int i = 1; i < temp.size(); i++) {
//         for (int j = 0; j < temp[i].size(); j++) {
//             bool exits = false; //标志某索引不在results中
//             for (int x = 0; x < results.size(); x++) {
//                 if (temp[i][j] == results[x]) {
//                     exits = true; //已经存在索引
//                     break;
//                 }
//             }
//             if (!exits) {
//                 results.push_back(temp[i][j]);
//             }
//             //不存在索引，就将这个索引存入results
//         }
//     }
//     return results;
// }

// //求交集
// std::vector<int> MainWindow::complex_and(std::vector<std::vector<int>>& temp) {
//     std::vector<int> results;
//     std::vector<int> to_delete;
//     for (int i = 0; i < temp.size(); i++)
//         if (temp[i].size() == 0)
//             to_delete.push_back(i);
//     //删除空的索引组
//     if (to_delete.size() != 0) {
//         for (int i = 0; i < to_delete.size(); i++)
//             temp.push_back(temp[to_delete[i]]);
//     }
//     //如果temp还有东西，说明过滤出东西来了
//     //过滤结果为空，返回一个空索引
//     if (temp.size() == 0) return results;

//     int min_length = temp[0].size(); //索引长度最小值的初始化
//     int min_index = 0;               //最小索引组的位置
//     int pass = 0;                    //交集元素个数
//     int deleted = 0;                 //不符合条件的个数
//     //找出索引最少的组
//     for (int i = 1; i < temp.size(); i++)
//         if (temp[i].size() < min_length) {
//             min_length = temp[i].size();
//             min_index = i;
//         }
//     for (int x = 0; x < min_length; x++) {
//         bool exist = false;
//         for (int y = 0; y < temp.size(); y++) {
//             if (y == min_index) continue; //跳过最少的那个组
//             exist = false;
//             //逐一判断，是否为其他索引组的交集元素
//             for (int z = 0; z < temp[y].size(); z++) {
//                 if (temp[min_index][x] == temp[y][z]) {
//                     exist = true;
//                     //是该索引组的交集元素
//                     break;
//                 }
//             }
//         }
//         //判断temp[min_index][x]是否为所有组的交集元素
//         if (exist) {
//             results.push_back(temp[min_index][x]);
//             pass++;
//         } else deleted++;

//         if (pass + deleted >= min_length) break;
//         //temp[min_index]中的元素都符合/都不符合
//     }
//     return results;
// }

// //求补集
// std::vector<int> MainWindow::fixed_result(const ProxyIntVector& temp) {
//     std::vector<int> results;
//     bool exist = false;
//     for (int i = 0; i < this->packets.size(); i++) {
//         exist = false;
//         for (int j = 0; j < temp.size(); j++)
//             if (i == temp[j]) {
//                 exist = true;
//                 break;
//             }
//         if (!exist) results.push_back(i);
//     }
//     return results;
// }
