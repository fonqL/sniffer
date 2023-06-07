#pragma once

#include "packet.h"
#include <QtSql>
#include <chrono>
#include <vector>

//
// 非线程安全
class ProxyVector {
    // size_t writeOffset;
    size_t sz;
    QSqlDatabase db;
    std::vector<pack> packets;

    size_t cacheOffset;
    std::vector<pack> readCache;

    // 在push_back pack进来时就对其序列化保存在缓存中，减小峰值开销。
    std::vector<QByteArray> blobCache;

    std::chrono::steady_clock::time_point lastTime;

private:
    bool is_activate() const;

    static void sql_assert(bool e) {
        [[unlikely]] if (!e)
            throw std::runtime_error{"sql error"};
    }

    void exec(const QString& s) {
        sql_assert(QSqlQuery{}.exec(s));
    }

    void archive();

public:
    ProxyVector();
    ProxyVector(const ProxyVector&) = delete;
    ProxyVector(ProxyVector&&) = delete;
    ProxyVector& operator=(ProxyVector&&) = delete;
    ProxyVector& operator=(const ProxyVector&) = delete;

    ~ProxyVector() { clear(); }

    size_t size() const { return sz; }
    bool empty() const { return sz == 0; }

    const pack& back() { return (*this)[sz - 1]; }
    const pack& at(size_t i) { return (*this)[i]; }
    const pack& operator[](size_t i);

    void push_back(pack&& x);

    void clear();
};
