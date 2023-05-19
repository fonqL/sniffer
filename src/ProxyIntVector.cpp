// #include "ProxyIntVector.h"
// #include <QDataStream>
// //

// static constexpr size_t LENGTH = 1'000'000;

// ProxyIntVector::ProxyIntVector()
//     : sz(0), count(1) {
// }

// bool ProxyIntVector::is_activate() const {
//     return count.back().size() >= LENGTH;
// }

// void ProxyIntVector::archive() {
//     count.push_back({});
// }

// void ProxyIntVector::push_back(int x) {
//     if (is_activate()) {
//         archive();
//     }
//     ++sz;
//     count.back().push_back(x);
// }

// int ProxyIntVector::operator[](size_t i) const {
//     return count[i / LENGTH][i % LENGTH];
// }

// void ProxyIntVector::clear() {
//     count.clear();
//     count.push_back({});
//     sz = 0;
// }
