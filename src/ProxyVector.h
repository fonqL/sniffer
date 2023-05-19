// #pragma once

// #include <QtSql>
// #include <any>
// #include <chrono>
// #include <vector>

// //

// class ProxyVector {
//     size_t offset;
//     size_t sz;
//     QSqlDatabase db;
//     std::vector<std::vector<std::any>> packets;
//     std::vector<QByteArray> blobCache;
//     std::chrono::steady_clock::time_point lastTime;

// private:
//     bool is_activate() const;

//     void sql_assert(bool e) {
//         if (!e) throw std::runtime_error{"sql error"};
//     }

//     void exec(const QString& s) {
//         sql_assert(QSqlQuery{}.exec(s));
//     }

//     void archive();

// public:
//     ProxyVector();

//     ~ProxyVector() { clear(); }

//     size_t size() const {
//         return sz;
//     }

//     const std::vector<std::any>&
//     at(size_t i) {
//         return (*this)[i];
//     }

//     const std::vector<std::any>&
//     operator[](size_t i);

//     void push_back(std::vector<std::any>&& x);

//     void clear();
// };