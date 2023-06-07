#pragma once
#include <memory>

// 抽象基类
struct ExprAST {
    virtual bool check(const class packet&) { return true; };
    virtual ~ExprAST() = default;
};

std::unique_ptr<ExprAST> compile(const class QString&);
