#
简单的网络嗅探器

## 项目简介

在windows上的、仿wireshark的、基于qt和npcap的网络嗅探器。
支持捕获网卡数据包并解析显示出各协议字段，支持以太帧/ip/ip6/icmp/arp/tcp/udp/dns协议
支持捕获过滤器和显示过滤器
支持保存文件与读取文件
具有基本的统计功能，并可以图表形式可视化

## 结构介绍

报文数据流：
npcap内核缓冲区
↓
↓         内核线程，设定为当内核收到一个包时，先等一下，再系统调用批量复制
↓
npcap用户缓冲区（原始包
↓
↓         用户线程，不间断阻塞式轮询
↓
SafeQueue环形缓冲区（已解析包
↓
↓         主进程，间断轮询并清空
↓         try/wait 和 one/many 构成正交关系，共有四种索取方式。最终用的是try_many，因为与展示串行处理，需要批量处理力
↓
tmp（已解析包
↓   ↓
↓   ↓      主进程，有反复处理也有批量处理
↓   ↓
↓   Qt的列表视图（字符串化
↓
↓     主进程，反复处理
↓
ProxyVector（已解析包

--------------------------------------------

展示：
解析的包
↓
↓     过滤器
↓
根据展示模式决定是否加入界面中

统计功能：
每隔一定时间对统计数据进行一次采样，可获得各类报文的趋势走向

## 难点

1. 协议的细节，详细阅读规范说明
    - 比如tcp协议上一些字段的长度不是字节的倍数，这时就需要c++的位域语法。位域的bit排布方式依赖于编译器实现。标准没定义。所以需要查阅msvc对位域的相关文档。
    - 字段的意义和取值的意义，需要用作字符串化。如icmp的type和code各种取值下的含义就需要通过查表来解析。
2. npcap和sqlite的细节优化，设置底层参数的接口（也是通读文档）
3. 显示过滤器的反射解析，比如协议.字段
    反射用于显示过滤器和序列化。具体来说需要对表示每个协议的struct配置类型名称、字段名称、序列化方法。其中显示过滤器对反射的需求最为复杂。需要输入字符串，输出对某个协议的某个字段的getter方法。糅杂了大量模板元编程技巧，比如操作类型、ifconstexpr、泛型可变参展开。最后擦除表达式树的类型选用了继承设计。
4. 报文的建模，协议集合（改进方向
5. 设计的模型，线程方面，甚至在耦合底层存档ProxyVector（改进方向

## 回应问题

常态cpu占用在15%左右，最高可达30%的cpu占用。

为什么不改进：仅仅是有个计划，目前实现的复杂度较简单，鉴于重构时间成本和额外复杂度暂时不重构，即目前就挺好的，因为不是实用项目，性能已经满意。

qt只对屏幕上显示出的元素 在获得焦点时或改变(发出append/remove信号)时 进行刷新(更新)指定位置上的数据。即与绘制同步。
