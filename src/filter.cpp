// #include "mainwindow.h"
#include "packet.h"
#include <QString>
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <mapbox/variant.hpp>
#include <mapbox/variant_cast.hpp>

namespace mb = mapbox::util;
//

//===----------------------------------------------------------------------===//
// 基础设施
//===----------------------------------------------------------------------===//

void verify(bool cond) {
    if (!cond) throw 0; //note: 因为错误也很常见所以不加unlikely了
}

template<bool C, class A, class B>
using if_t = std::conditional_t<C, A, B>;

template<class T, class R>
using Getter = auto(const T&) -> R;

class input_adapter {
    QString buf;
    qsizetype idx;

public:
    input_adapter(const QString& s) : buf(s), idx(0) {}
    QChar get() {
        [[unlikely]] if (idx >= buf.size())
            return QChar::Null;
        return buf[idx++];
    }
};

//===----------------------------------------------------------------------===//
// 词法分析
//===----------------------------------------------------------------------===//

enum tok_type {
    paren_begin,
    paren_end,
    eq,
    neq,
    le,
    lt,
    ge,
    gt,
    not_,
    and_,
    or_,
    number,
    mac,
    ip4,
    ip6,
    proto,
    proto_field,
};

template<tok_type... ts>
struct tok_list {};

constexpr tok_list<eq, neq, lt, le, gt, ge> ValidOps;

uint prec(tok_type t) {
    switch (t) {
    case or_: return 1;
    case and_: return 2;
    default: return 0;
    }
}

using tok_val = mb::variant<uint,
                            QString,
                            // todo 要改为std::vector<QString>了？？因为tcp。。
                            // 。暂时不支持
                            std::pair<QString, QString>,
                            IPv4Addr,
                            IPv6Addr,
                            MacAddr>;

constexpr mb::no_init noinit;

struct tok {
    tok_type type;
    tok_val value;
};

class lexer {
    input_adapter ia;
    QChar last_char;

    QChar get() { return last_char = ia.get(); }
    void skipspace() {
        while (last_char.isSpace() || last_char == '\t')
            get();
    }

public:
    lexer(const QString& s) : ia(s), last_char(ia.get()) {}

    template<class T>
    T scan_type() {
        skipspace();
        verify(last_char.isNumber());
        if constexpr (std::is_same_v<T, uint>) {
            QString s;
            do {
                s += last_char;
            } while (get().isNumber());
            s.toStdString();

            bool ok;
            uint n = s.toUInt(&ok);
            verify(ok);
            return n;
        } else if constexpr (std::is_same_v<T, IPv4Addr>) {
            std::string s;
            do {
                s += char(last_char.unicode());
                get();
            } while (last_char.isNumber() || last_char == '.');

            IPv4Addr addr;
            verify(inet_pton(AF_INET, s.c_str(), addr.data()) == 1);
            return addr;
        } else {
            std::string s;
            do {
                s += char(last_char.unicode());
                get();
            } while (last_char.isNumber() || last_char == ':');

            if constexpr (std::is_same_v<T, MacAddr>) {
                MacAddr addr;
                verify(sscanf(s.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                              &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5])
                       == 6);
                return addr;
            } else {
                static_assert(std::is_same_v<T, IPv6Addr>);

                IPv6Addr addr;
                verify(inet_pton(AF_INET6, s.c_str(), addr.data()) == 1);
                return addr;
            }
        }
    }

    // value depends on input string
    tok scan() {
        skipspace();
        if (std::isalpha(last_char.unicode())) {
            QString ptc;
            do {
                ptc += last_char;
            } while (std::isalpha(get().unicode()));

            if (last_char == '.') {
                QString field;
                while (std::isalpha(get().unicode())) {
                    field += last_char;
                }
                return {proto_field, std::pair(ptc, field)};
            } else {
                return {proto, ptc};
            }
        } else if (last_char == '(') {
            get();
            return {paren_begin, noinit};
        } else if (last_char == ')') {
            get();
            return {paren_end, noinit};
        } else if (last_char == '=') {
            verify(get() == '=');
            get();
            return {eq, noinit};
        } else if (last_char == '!') {
            if (get() == '=')
                return get(), tok{neq, noinit};
            else
                return {not_, noinit};
        } else if (last_char == '<') {
            if (get() == '=')
                return get(), tok{le, noinit};
            else
                return {lt, noinit};
        } else if (last_char == '>') {
            if (get() == '=')
                return get(), tok{ge, noinit};
            else
                return {gt, noinit};
        } else if (last_char == '&') {
            verify(get() == '&');
            get();
            return {and_, noinit};
        } else {
            verify(last_char == '|');
            verify(get() == '|');
            get();
            return {or_, noinit};
        }
    }
};

//===----------------------------------------------------------------------===//
// 抽象语法树
//===----------------------------------------------------------------------===//

// 抽象基类
struct ExprAST {
    virtual bool check(const packet&) = 0;
    virtual ~ExprAST() = default;
};

// 两两bool表达式的组合
template<tok_type Op>
struct BinaryAST : ExprAST {
    std::unique_ptr<ExprAST> l, r;

    BinaryAST(std::unique_ptr<ExprAST> l, std::unique_ptr<ExprAST> r)
        : l(std::move(l)), r(std::move(r)) {}

    bool check(const packet& x) override {
        if constexpr (Op == and_)
            return l->check(x) && r->check(x);
        else
            return l->check(x) || r->check(x);
    }
};

// not单目运算符
struct UnaryAST : ExprAST {
    std::unique_ptr<ExprAST> expr;

    UnaryAST(std::unique_ptr<ExprAST> e) : expr(std::move(e)) {}
    bool check(const packet& x) override { return !expr->check(x); }
};

template<class T>
struct ProtoExprAST : ExprAST {
    bool check(const packet& x) override { return x.get<T>() != nullptr; }
};

template<tok_type Op, class T, class R>
struct ProtoFieldExprAST : ExprAST {
    Getter<T, R>* getter;
    R val;

    ProtoFieldExprAST(Getter<T, R>* func, R x) : getter(func), val(std::move(x)) {}
    bool check(const packet& x) override {
        if (auto* proto = x.get<T>()) {
            if constexpr (Op == eq) return getter(*proto) == val;
            else if constexpr (Op == neq) return getter(*proto) != val;
            else if constexpr (Op == le) return getter(*proto) < val;
            else if constexpr (Op == lt) return getter(*proto) <= val;
            else if constexpr (Op == ge) return getter(*proto) >= val;
            else return getter(*proto) > val;

        } else return false;
    }
};

//===----------------------------------------------------------------------===//
// 构造或静态语法解析
//===----------------------------------------------------------------------===//

std::unique_ptr<ExprAST> mkBinary(tok_type op, std::unique_ptr<ExprAST> l, std::unique_ptr<ExprAST> r) {
    if (op == and_)
        return std::make_unique<BinaryAST<and_>>(std::move(l), std::move(r));
    else {
        verify(op == or_);
        return std::make_unique<BinaryAST<or_>>(std::move(l), std::move(r));
    }
}

//

template<class T>
bool mkPrt_case(const QString& proto_str, std::unique_ptr<ExprAST>& out) {
    if (proto_str == T::name) {
        out = std::make_unique<ProtoExprAST<T>>();
        return true;
    }
    return false;
}
template<class... Ts>
std::unique_ptr<ExprAST> mkPrt_match(const QString& proto_str, type_list<Ts...>) {
    std::unique_ptr<ExprAST> ret = nullptr;
    verify((mkPrt_case<Ts>(proto_str, ret) || ...));
    return ret;
}

//

template<class T, class R, tok_type t>
bool mkPF_case(tok_type op, Getter<T, R>* func, R&& val, std::unique_ptr<ExprAST>& out) {
    if (op == t) {
        out = std::make_unique<ProtoFieldExprAST<t, T, R>>(func, std::move(val));
        return true;
    }
    return false;
}
template<class T, class R, tok_type... ts>
std::unique_ptr<ExprAST> mkPF_match(tok_type op, Getter<T, R>* func, R&& val, tok_list<ts...>) {
    std::unique_ptr<ExprAST> ret = nullptr;
    verify((mkPF_case<T, R, ts>(op, func, std::move(val), ret) || ...));
    return ret;
}
//===----------------------------------------------------------------------===//
// 语法解析
//===----------------------------------------------------------------------===//

#define FIELD_CASE(field)                                        \
    {                                                            \
        static const QString field_name = #field;                \
        if (field_str == field_name) {                           \
            using rawR = decltype(((T*)nullptr)->field);         \
            using R = if_t<std::is_enum_v<rawR>, uint, rawR>;    \
            using ParseR = if_t<std::is_integral_v<R>, uint, R>; \
            return ::mkPF_match<T, R>(                           \
                op, +[](const T& x) -> R { return x.field; },    \
                lex.scan_type<ParseR>(), ValidOps);              \
        }                                                        \
    }

#define PROTO_MATCH \
    if constexpr (false) {}

#define PROTO_CASE(proto) \
    else if constexpr (std::is_same_v<T, proto>)

class parser {
private:
    //===------------------------------------------------------------------===//
    // RL-类型依赖语法解析，需要this.lexer，所以必须是成员函数
    //===------------------------------------------------------------------===//
    template<class T>
    std::unique_ptr<ExprAST> parse_field(const QString& field_str) {
        auto op = last_tok.type;
        verify(op == eq || op == neq || op == le || op == lt || op == ge || op == gt);
        get();

        PROTO_MATCH
        PROTO_CASE(eth_header) {
            FIELD_CASE(src);
            FIELD_CASE(dst);
            FIELD_CASE(len);
            FIELD_CASE(type);
        }
        PROTO_CASE(arp_packet) {
            FIELD_CASE(hardware_type);
            FIELD_CASE(proto_type);
            FIELD_CASE(mac_len);
            FIELD_CASE(ip_len);
            FIELD_CASE(op);
            FIELD_CASE(src_mac);
            FIELD_CASE(src_ip);
            FIELD_CASE(dst_mac);
            FIELD_CASE(dst_ip);
        }
        PROTO_CASE(ipv4_header) {
            FIELD_CASE(version);
            FIELD_CASE(header_len);
            FIELD_CASE(ds);
            FIELD_CASE(len);
            FIELD_CASE(id);
            FIELD_CASE(df);
            FIELD_CASE(mf);
            FIELD_CASE(offset);
            FIELD_CASE(ttl);
            FIELD_CASE(proto);
            FIELD_CASE(checksum);
            FIELD_CASE(src);
            FIELD_CASE(dst);
        }
        PROTO_CASE(ipv6_header) {
            FIELD_CASE(version);
            FIELD_CASE(traffic_class);
            FIELD_CASE(flow_label);
            FIELD_CASE(payload_len);
            FIELD_CASE(next_header);
            FIELD_CASE(hop_limit);
            FIELD_CASE(src);
            FIELD_CASE(dst);
        }
        PROTO_CASE(icmp_packet) {
            FIELD_CASE(type);
            FIELD_CASE(code);
            FIELD_CASE(checksum);
            FIELD_CASE(field);
        }
        PROTO_CASE(tcp_header) {
            FIELD_CASE(src);
            FIELD_CASE(dst);
            FIELD_CASE(seq);
            FIELD_CASE(ack);
            FIELD_CASE(header_len);
            // FIELD_CASE(flags);
            FIELD_CASE(window_size);
            FIELD_CASE(checksum);
            FIELD_CASE(urgent_ptr);
        }
        PROTO_CASE(udp_header) {
            FIELD_CASE(src);
            FIELD_CASE(dst);
            FIELD_CASE(len);
            FIELD_CASE(checksum);
        }
        else {
            static_assert(std::is_same_v<T, dns_packet>);
            FIELD_CASE(id);
            // FIELD_CASE(flags);
            FIELD_CASE(questions);
            FIELD_CASE(answer_rrs);
            FIELD_CASE(authority_rrs);
            FIELD_CASE(additional_rrs);
        }
        throw 0; // 没有找到field
    }

    template<class T>
    bool parsePF_case(const QString& proto_str, const QString& field_str, std::unique_ptr<ExprAST>& out) {
        if (proto_str == T::name) {
            out = parse_field<T>(field_str);
            return true;
        }
        return false;
    }

    template<class... Ts>
    std::unique_ptr<ExprAST> parsePF_match(const QString& proto_str, const QString& field_str, type_list<Ts...>) {
        std::unique_ptr<ExprAST> ret = nullptr;
        verify((parsePF_case<Ts>(proto_str, field_str, ret) || ...));
        return ret;
    }

private:
    lexer lex;
    tok last_tok;

public:
    parser(const QString& s) : lex(s), last_tok(lex.scan()) {}
    std::unique_ptr<ExprAST> parse() try {
        return parseExpr();
    } catch (...) { return nullptr; }

private:
    tok& get() { return last_tok = lex.scan(); }

    std::unique_ptr<ExprAST> parseExpr() {
        return parseBinTail(parseBinHead());
    }

    std::unique_ptr<ExprAST> parseBinHead() {
        if (last_tok.type == paren_begin)
            return parseParen();
        if (last_tok.type == not_)
            return parseUnary();
        if (last_tok.type == proto)
            return parseProto();
        verify(last_tok.type == proto_field);
        return parseProtoField();
    }

    std::unique_ptr<ExprAST> parseBinTail(std::unique_ptr<ExprAST> prehead) {
        tok_type op1 = last_tok.type;
        if (op1 != and_ && op1 != or_)
            return prehead;
        get();
        auto head = parseBinHead();
        tok_type op2 = last_tok.type;
        // note: 不能get(), op2留给下个parse消耗
        if (prec(op1) > prec(op2))
            return parseBinTail(::mkBinary(op1, std::move(prehead), std::move(head)));
        else
            return ::mkBinary(op1, std::move(prehead), parseBinTail(std::move(head)));
    }

    std::unique_ptr<ExprAST> parseUnary() {
        // assert last_tok.type == not_
        get();
        std::unique_ptr<ExprAST> x;
        if (last_tok.type == paren_begin) {
            x = parseParen();
        } else {
            verify(last_tok.type == proto);
            x = parseProto();
        }
        return std::make_unique<UnaryAST>(std::move(x));
    }

    std::unique_ptr<ExprAST> parseParen() {
        // assert last_tok.type == paren_begin
        get();
        auto res = parseExpr();
        verify(last_tok.type == paren_end);
        get();
        return res;
    }

    // value parse

    std::unique_ptr<ExprAST> parseProto() {
        // assert last_tok.type == proto
        auto& name = mb::static_variant_cast<QString&>(last_tok.value);
        auto ret = ::mkPrt_match(name, ValidProtos{});
        get();
        return ret;
    }

    std::unique_ptr<ExprAST> parseProtoField() {
        auto& pf = mb::static_variant_cast<std::pair<QString, QString>&>(last_tok.value);
        auto& proto_str = pf.first;
        auto& field_str = pf.second;
        get();
        auto ret = parsePF_match(proto_str, field_str, ValidProtos{});
        get();
        return ret;
    }
};

#undef FIELD_CASE
#undef PROTO_MATCH
#undef PROTO_CASE
