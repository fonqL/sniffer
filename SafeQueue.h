#include <condition_variable>
#include <memory>
#include <mutex>

using T = std::string;
class SafeQueue {
    static_assert(std::is_nothrow_move_assignable_v<T>);
    static_assert(std::is_nothrow_move_constructible_v<T>);

    struct Node {
        std::unique_ptr<Node> next; //stackoverflow kusa.但是设定pophead。。单链表不能poptail
        T data;
    };

    std::unique_ptr<Node> header;
    std::mutex headerMutex;

    //约定tail指向的节点data为空
    Node* tail;
    std::mutex tailMutex;

    std::condition_variable notEmpty;

private:
    Node* getTail() {
        std::scoped_lock lock{tailMutex};
        return tail;
    }

public:
    SafeQueue()
        : header(std::make_unique<Node>()),
          tail(header.get()) {
    }

    void push(T newdata) {
        auto newtail = std::make_unique<Node>();
        auto ptr = newtail.get();
        [&, lock = std::scoped_lock{tailMutex}]() {
            tail->data = std::move(newdata);
            tail->next = std::move(newtail);
            tail = ptr;
        }();
        notEmpty.notify_one();
    }

    T blockPop() {
        return [&, lock = std::unique_lock{headerMutex}]() mutable { //
            notEmpty.wait(lock, [&, header = header.get()]() {       //
                return header != getTail();
            });
            auto ret = std::move(header->data);
            header = std::move(header->next);
            return ret;
        }();
    }

    //如果需要不阻塞的，允许失败的pop以后再写

    bool isEmpty() {
        std::scoped_lock lock{headerMutex};
        return header.get() == getTail();
    }
};
