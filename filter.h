//#include "mainwindow.h"
#include <regex>
#include <sstream>
#include <string>

/*----------��ʾ��������һЩ����&��������--------*/
std::regex _empty(" ");//ȥ���ո�
std::regex _and(" and ");//�ؼ��ַ�
std::regex _or(" or ");
std::regex _bigger(">");//�����
std::regex _smaller("<");
std::regex _big_or_eq(">=");
std::regex _small_or_eq("<=");
std::regex _equal("==");
std::regex _not_eq("!=");

/*-----------------------------------------------------------------*/
/*
    --ip��port��֧��==����
    --���ְ���len֧��>��<=�������
    --������ֻ����ֻ����and/or,���磺
        tcp and dns and ip=0.0.0.0 ��
        udp or tcp or !ipv4        ��
        tcp and ipv4 or !dns       ��
        (��Ҫ�����̫�����ˣ����ø���)
    --ֵƥ�䣺
        ip|ip.dst|ip.src|port
        tcp.port|tcp.dst|tcp.src
        udp.port|udp.dst|udp.src
        len|ipv4.len|.....|tcp.len
*/
//�ж��ǲ���һ���Ϸ��Ĺ������
bool MainWindow::is_a_sentence(QString fil)
{
    std::string filter = fil.toStdString();
    if (std::regex_match(filter, std::regex(" *")))//�����	
        return false;
    else if (std::regex_search(filter, _and))//and���
    {
        std::vector<std::string> filt = split_and(filter);
        for (int i = 0;i < filt.size();i++)
        {
            if (is_a_filter(filt[i]) == false)
                return false;
        }
        return true;
    }
    else if (std::regex_search(filter, _or))//or���
    {
        std::vector<std::string> filt = split_or(filter);
        for (uint i = 0;i < filt.size();i++)
        {
            if (is_a_filter(filt[i]) == false)
                return false;
        }
        return true;
    }
    else //���Ӿ�
    {
        return is_a_filter(filter);
    }
    //false������������ȷ�Ĺ������
}

//�ж��Ӿ���û���﷨����
bool MainWindow::is_a_filter(std::string filter)
{
    //�˿ڷ�Χ��0-65535�������ᱨ��
    //ip��Χ��0.0.0.0--255.255.255.255
    if (std::regex_match(filter, std::regex(" *arp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *tcp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *udp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *icmp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *dns *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *ipv4 *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *ipv6 *", std::regex::icase)))
        return true;

    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;

    //����==
    else if (std::regex_match(filter, std::regex("^ *len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *== *[1-9][0-9]* *$")))//arp�����ȣ�����ͬ��
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *== *[1-9][0-9]* *$")))
        return true;

    //����>=
    else if (std::regex_match(filter, std::regex("^ *len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *>= *[1-9][0-9]* *$")))
        return true;

    //����<=
    else if (std::regex_match(filter, std::regex("^ *len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *<= *[1-9][0-9]* *$")))
        return true;

    //����>
    else if (std::regex_match(filter, std::regex("^ *len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *> *[1-9][0-9]* *$")))
        return true;

    //����<
    else if (std::regex_match(filter, std::regex("^ *len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *< *[1-9][0-9]* *$")))
        return true;

    //ֵ����,���磺ip != 0.0.0.0
    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *!= *[1-9][0-9]* *$")))
        return true;

    //����ĳЭ��,���磺 !dns
    if (std::regex_match(filter, std::regex(" *!arp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!tcp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!udp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!icmp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!dns *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!ipv4 *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!ipv6 *", std::regex::icase)))
        return true;

    else
        return false;
}

//����ץ���İ�,������صĳ���
std::vector<int> MainWindow::catched_filter(std::string s)
{
    if (std::regex_search(s, _and))//and���
    {
        std::vector <std::vector<int>> temp;
        std::vector<std::string> filt = split_and(s);
        //�����Ӿ䣬���������temp
        for (int i = 0;i < filt.size();i++)
        {
            temp.push_back(analyse_filter(filt[i]));
        }
        return complex_and(temp);
    }
    else if (std::regex_search(s, _or))//or���
    {
        std::vector <std::vector<int>> temp;
        std::vector<std::string> filt = split_or(s);
        for (int i = 0;i < filt.size();i++)
        {
            temp.push_back(analyse_filter(filt[i]));
        }
        return complex_or(temp);
    }
    //���Ӿ�ֱ�Ӷ���analyse_filter()���ܵó������
    else return analyse_filter(s);
}

//�����Ӿ�,����һ����������
std::vector<int> MainWindow::analyse_filter(std::string filter)
{
    //Ԥ����������������ֵ��ȡ��������set_data
    std::vector<std::string> temp_data;
    std::string set_data;
    std::vector<int> results;
    if ((std::regex_search(filter, _equal)))// ==
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _equal, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _big_or_eq)))// >=
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _big_or_eq, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _small_or_eq)))// <=
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _small_or_eq, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _smaller)))// <
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _smaller, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _bigger)))// >
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _bigger, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _not_eq)))
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _not_eq, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }

    //��Э��
    if (std::regex_match(filter, std::regex(" *arp *", std::regex::icase)))//arpЭ��
        return	this->count.arp_c;
    else if (std::regex_match(filter, std::regex(" *tcp *", std::regex::icase)))
        return this->count.tcp_c;
    else if (std::regex_match(filter, std::regex(" *udp *", std::regex::icase)))
        return this->count.udp_c;
    else if (regex_match(filter, std::regex(" *icmp *", std::regex::icase)))
        return this->count.icmp_c;
    else if (regex_match(filter, std::regex(" *dns *", std::regex::icase)))
        return this->count.dns_c;
    else if (regex_match(filter, std::regex(" *ipv4 *", std::regex::icase)))
        return this->count.ipv4_c;
    else if (std::regex_match(filter, std::regex(" *ipv6 *", std::regex::icase)))
        return this->count.ipv6_c;//������ȡ��
    else if (std::regex_match(filter, std::regex(" *!arp *", std::regex::icase)))
        return	fixed_result(this->count.arp_c);
    else if (std::regex_match(filter, std::regex(" *!tcp *", std::regex::icase)))
        return fixed_result(this->count.tcp_c);
    else if (std::regex_match(filter, std::regex(" *!udp *", std::regex::icase)))
        return fixed_result(this->count.udp_c);
    else if (regex_match(filter, std::regex(" *!icmp *", std::regex::icase)))
        return fixed_result(this->count.icmp_c);
    else if (regex_match(filter, std::regex(" *!dns *", std::regex::icase)))
        return fixed_result(this->count.dns_c);
    else if (regex_match(filter, std::regex(" *!ipv4 *", std::regex::icase)))
        return fixed_result(this->count.ipv4_c);
    else if (std::regex_match(filter, std::regex(" *!ipv6 *", std::regex::icase)))
        return fixed_result(this->count.ipv6_c);

    //Դ��Ŀ��IP��ַ
    else if (std::regex_match(filter, std::regex("^ *ip *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved1 = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            std::string saved2 = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if ((saved1 == set_data) || (saved2 == set_data))
                results.push_back(i);
        }
        return results;
    }
    //Ŀ��ip��ַ
    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if (saved == set_data)
                results.push_back(i);
        }
        return results;
    }
    //Դip��ַ
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            if (saved == set_data)
                results.push_back(i);
        }
        return results;
    }

    //TCPĿ�Ķ˿�
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.dst;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //TCPԴ�˿�
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.src;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //TCPԴ��Ŀ�Ķ˿�
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {

        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        return results;
    }

    //UDPĿ�Ķ˿�
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.dst;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //UDPԴ�˿�
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.src;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //UDPԴ��Ŀ�Ķ˿�
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        return results;
    }

    //���ж˿�
    else if (std::regex_match(filter, std::regex("^ *port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        return results;
    }

    //��������
    //����==
    else if (std::regex_match(filter, std::regex("^ *len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *== *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *== *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    //����>=
    else if (std::regex_match(filter, std::regex("^ *len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *>= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved >= trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *>= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved >= trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }
    //����<=
    else if (std::regex_match(filter, std::regex("^ *len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *<= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved <= trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *<= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved <= trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }
    //����<
    else if (std::regex_match(filter, std::regex("^ *len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *< *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved < trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *< *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved < trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }
    //����>
    else if (std::regex_match(filter, std::regex("^ *len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *> *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved > trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *> *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved > trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }

    //���ֲ��ȹ�ϵ!=
    else if (std::regex_match(filter, std::regex("^ *ip *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved1 = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            std::string saved2 = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if ((saved1 != set_data) && (saved2 != set_data))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if (saved != set_data)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            if (saved != set_data)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.dst;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.src;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {

        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.dst;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.src;
            uint16_t trans;//��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //ʹ��stringstream ��set_data ת��uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *!= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *!= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else
    {
        //��һ�£����ؿ�vector
        std::vector<int> not_found;
        return not_found;
    }
}

//�ָ�and���
std::vector<std::string> MainWindow::split_and(std::string filter)
{
    std::vector <std::string>filt;
    std::sregex_token_iterator beg(filter.begin(), filter.end(), _and, -1);
    std::sregex_token_iterator end; //������־
    for (; beg != end; beg++)
    {
        filt.push_back(beg->str());
    }
    return filt;
}

//�ָ�or���
std::vector<std::string> MainWindow::split_or(std::string filter)
{
    std::vector <std::string>fff;
    std::sregex_token_iterator beg(filter.begin(), filter.end(), _or, -1);
    std::sregex_token_iterator end; //������־
    for (; beg != end; beg++)
    {
        fff.push_back(beg->str());
    }
    return fff;
}

//�󲢼�
std::vector<int> MainWindow::complex_or(std::vector<std::vector<int>>temp)
{
    std::vector<int> results;
    std::vector<int> to_delete;

    for (int i = 0;i < temp.size();i++)
        if (temp[i].size() == 0)
            to_delete.push_back(i);
    //ɾ���յ�������
    if (to_delete.size() != 0)
    {
        for (int i = 0;i < to_delete.size();i++)
            temp.push_back(temp[to_delete[i]]);
    }
    //���temp���ж�����˵�����˳���������
    //�õ�һ���������ʼ��
    if (temp.size() != 0)
    {
        for (int i = 0;i < temp[0].size();i++)
            results.push_back(temp[0][i]);
    }
    else return results;//����һ��������
    //��temp����һ�жϣ�
    //��i����������ĵ�j��Ԫ�� �Ƿ� ��results��
    for (int i = 1;i < temp.size();i++)
    {
        for (int j = 0;j < temp[i].size();j++)
        {
            bool exits = false;//��־ĳ��������results��	
            for (int x = 0;x < results.size();x++)
            {
                if (temp[i][j] == results[x])
                {
                    exits = true;//�Ѿ���������
                    break;
                }
            }
            if (!exits)
            {
                results.push_back(temp[i][j]);
            }
            //�������������ͽ������������results
        }
    }
    return results;
}

//�󽻼�
std::vector<int> MainWindow::complex_and(std::vector<std::vector<int>>temp)
{
    std::vector<int> results;
    std::vector<int> to_delete;
    for (int i = 0;i < temp.size();i++)
        if (temp[i].size() == 0)
            to_delete.push_back(i);
    //ɾ���յ�������
    if (to_delete.size() != 0)
    {
        for (int i = 0;i < to_delete.size();i++)
            temp.push_back(temp[to_delete[i]]);
    }
    //���temp���ж�����˵�����˳���������
    //���˽��Ϊ�գ�����һ��������
    if (temp.size() == 0)return results;

    int min_length = temp[0].size();//����������Сֵ�ĳ�ʼ��
    int min_index = 0;//��С�������λ��
    int pass = 0;//����Ԫ�ظ���
    int deleted = 0;//�����������ĸ���
    //�ҳ��������ٵ���
    for (int i = 1;i < temp.size();i++)
        if (temp[i].size() < min_length)
        {
            min_length = temp[i].size();
            min_index = i;
        }
    for (int x = 0;x < min_length;x++)
    {
        bool exist = false;
        for (int y = 0;y < temp.size();y++)
        {
            if (y == min_index)continue;//�������ٵ��Ǹ���
            exist = false;
            //��һ�жϣ��Ƿ�Ϊ����������Ľ���Ԫ��
            for (int z = 0;z < temp[y].size();z++)
            {
                if (temp[min_index][x] == temp[y][z])
                {
                    exist = true;
                    //�Ǹ�������Ľ���Ԫ��
                    break;
                }
            }
        }
        //�ж�temp[min_index][x]�Ƿ�Ϊ������Ľ���Ԫ��
        if (exist)
        {
            results.push_back(temp[min_index][x]);
            pass++;
        }
        else deleted++;

        if (pass + deleted >= min_length)break;
        //temp[min_index]�е�Ԫ�ض�����/��������
    }
    return results;
}

//�󲹼�
std::vector<int> MainWindow::fixed_result(std::vector<int>temp)
{
    std::vector<int> results;
    bool exist = false;
    for (int i = 0;i < this->packets->size();i++)
    {
        exist = false;
        for (int j = 0;j < temp.size();j++)
            if (i == temp[j])
            {
                exist = true;
                break;
            }
        if (!exist)results.push_back(i);
    }
    return results;
}
