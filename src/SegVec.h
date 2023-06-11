// #pragma once

// #include <vector>
// //

// // 分块vector，以免发生过大内存分配
// // 要减少扩容时的开销。。强化实时性。。
// // 怀疑必要性。。但未做过长时间占用大量内存时的性能测试，所以保留
// class ProxyIntVector {
//     size_t sz;
//     std::vector<std::vector<int>> count;

// private:
//     bool is_activate() const noexcept;

//     void archive();

// public:
//     ProxyIntVector();

//     ProxyIntVector(const ProxyIntVector&) = delete;
//     ProxyIntVector(ProxyIntVector&&) = delete;
//     ProxyIntVector& operator=(const ProxyIntVector&) = delete;
//     ProxyIntVector& operator=(ProxyIntVector&&) = delete;
//     ~ProxyIntVector() = default;

//     size_t size() const noexcept {
//         return sz;
//     }

//     int at(size_t i) const noexcept {
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
