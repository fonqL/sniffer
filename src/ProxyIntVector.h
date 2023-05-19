// #pragma once

// #include <QVector>
// //

// // 分块vector，以免发生过大内存分配
// // 要减少扩容时的开销。。强化实时性。。
// class ProxyIntVector {
//     size_t sz;
//     QVector<QVector<int>> count;

// private:
//     bool is_activate() const;

//     void archive();

// public:
//     ProxyIntVector();

//     size_t size() const {
//         return sz;
//     }

//     int at(size_t i) const {
//         return (*this)[i];
//     }

//     int operator[](size_t i) const;

//     void push_back(int x);

//     void clear();

//     operator std::vector<int>() const {
//         std::vector<int> ret;
//         for (auto& i: count)
//             for (auto j: i)
//                 ret.push_back(j);
//         return ret;
//     }
// };
