blobCache
ProxyVector存档条件：
大于一定长度 且 存档cd(冷却时间)结束


packet建模为
kn..-k2-k1-v1-v2-..vn
共享一块双向扩容内存

协议最多只有一个变长字段且在最后，用`n+arr[0]`建模

ProxyVector弃用所有反射

使用sql索引rowid

sqlite3_limit(db,SQLITE_LIMIT_LENGTH,size)也有优化，但是qt如果要用sqlite裸api太麻烦了（也不麻烦？找到对应版本的sqlite然后qsqldriver::handle取出裸sqlite-handle就可以了。。据说还要sqlite3_initialize..
总之先不做。。

sqlite有without rowid。。看了看直接用rowid当主键就好了。without rowid用b树，而rowid用b*树(叶子结点存信息)。所以用rowid


~~ProxyVector换页时，取 以i为中心前后LENGTH/2 的页~~ 迭代时太浪费了，普通的以i向pagesize下取整为起点就好

filter做好了！大成功！！

适配filter

常数互质一下，以免碰撞导致峰值耗时突然增高

## 性能优化

[](image/1.png)
局部火焰图，总体火焰图没发现MWcapture, 多线程parse居然比MWcapture更瓶颈
QDateTime + std::chrono::milliseconds 慢的要死。。居然跟parse_packet一个速度。。
parse_packet(parse_datalink)有一半慢在packet.add上，完全是因为扩容时的内存分配与回收。。离谱，暂时不理

改进后：
[](image/2.png)
线程分析看到在1s内突发流量在10000个包以下时，parse多线程cpu占比不超过0.5%，在火焰图上已经找不到
主线程占比99.5%，MW::capture()占比1/7，主要耗在：qt界面上，vector的构造/析构，序列化存档。
[](image/3.png)
但序列化存档完全不是瓶颈，只占MW::capture()的1/14，几乎和vector析构差不多效率，赢麻了

更高流量冲击下：10000个包/s以上，3M/s吧大概，主线程占比更加离谱达到100%，解析报文线程忽略不计了
MW::capture()占总比达到27%。（有可能挂后台了所以qt渲染轻松了一点？
MW::capture()分布还是那样，锅都在qt

