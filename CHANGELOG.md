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

火焰图发现QDateTime + std::chrono::milliseconds 慢的要死。。居然跟parse_packet一个速度。。
parse_packet(parse_datalink)有一半慢在packet.add上，完全是因为扩容时的内存分配与回收。。离谱，暂时不理

