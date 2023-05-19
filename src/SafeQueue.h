#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

template<typename T>
class SafeQueue {
    static_assert(std::is_nothrow_default_constructible_v<T>);
    static_assert(std::is_nothrow_move_assignable_v<T>);
    static_assert(std::is_nothrow_move_constructible_v<T>);

    using capacity_t = uint16_t;

    static constexpr size_t CAPACITY = 1u << (sizeof(capacity_t) * 8);

    std::unique_ptr<std::optional<T>[]> circleBuffer;

    capacity_t header;
    capacity_t tail;
    // 环形队列要额外维护size，tail有可能小于header
    size_t size;
    // 大锁
    std::mutex mtx;

    std::condition_variable cv;

public:
    SafeQueue() : circleBuffer(new std::optional<T>[CAPACITY]), header(0), tail(0), size(0){};
    ~SafeQueue() = default;

    SafeQueue(const SafeQueue&) = delete;
    SafeQueue(SafeQueue&&) = delete;
    SafeQueue& operator=(const SafeQueue&) = delete;
    SafeQueue& operator=(SafeQueue&&) = delete;

public:
    bool push(T&& newdata, std::chrono::seconds sec) {
        {
            std::unique_lock lock{mtx};
            cv.wait_for(lock, sec, [&]() { return size != CAPACITY; });
            if (size == CAPACITY) return false;
            circleBuffer[tail] = std::move(newdata);
            tail++;
            size++;
        }
        cv.notify_one();
        return true;
    }

    T waitPop() {
        T ret;
        {
            std::unique_lock lock{mtx};
            cv.wait(lock, [&]() {
                return size != 0;
            });
            ret = std::move(circleBuffer[header].value());
            circleBuffer[header].reset();
            header++;
            size--;
        }
        cv.notify_one();
        return ret;
    }

    std::optional<T> tryPop() {
        std::optional<T> ret;
        {
            std::scoped_lock lock{mtx};
            if (header == tail)
                return std::nullopt;
            ret = std::move(circleBuffer[header].value());
            circleBuffer[header].reset();
            header++;
            size--;
        }
        cv.notify_one();
        return ret;
    }

    std::vector<T> popAll() {
        std::vector<T> ret;
        {
            std::scoped_lock lock{mtx};
            ret.reserve(size);
            while (size > 0) {
                ret.emplace_back(std::move(circleBuffer[header].value()));
                circleBuffer[header].reset();
                header++;
                size--;
            }
        }
        cv.notify_one();
        return ret;
    }
};
