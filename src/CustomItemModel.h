#pragma once

#include <QAbstractItemModel>

class mydeque {
private:
    std::vector<std::optional<std::vector<QString>>> circleBuffer;
    size_t header;
    size_t tail;
    size_t sz;

private:
    size_t inc(size_t x, size_t n) const {
        x += n;
        if (x >= circleBuffer.size())
            x -= circleBuffer.size();
        return x;
    }

public:
    mydeque()
        : circleBuffer(128), header(0), tail(0), sz(0) {
    }

    size_t size() const noexcept { return sz; }

    const std::vector<QString>& operator[](size_t i) const noexcept {
        return circleBuffer[inc(header, i)].value();
    }

    void push_back(std::vector<QString>&& x) {
        if (sz >= circleBuffer.size()) {
            decltype(circleBuffer) tmp(circleBuffer.size() * 2);
            for (size_t i = 0, j = header, k = 0; k < sz; ++i, inc(j, 1), ++k) {
                tmp[i] = std::move(circleBuffer[j]);
            }
            circleBuffer = std::move(tmp);
            header = 0;
            tail = sz;
        }
        circleBuffer[tail] = std::move(x);
        tail = inc(tail, 1);
        ++sz;
    }

    void pop_front() noexcept {
        circleBuffer[header].reset();
        header = inc(header, 1);
        --sz;
    }

    void clear() noexcept {
        header = tail = sz = 0;
        std::fill(circleBuffer.begin(), circleBuffer.end(), std::nullopt);
    }
};

//优化滚屏性能
class CustomItemModel
    : public QAbstractItemModel {
    Q_OBJECT

public:
    explicit CustomItemModel(QObject* parent = nullptr, std::vector<QString>&& header = {})
        : QAbstractItemModel(parent),
          m_header(std::move(header)) {
    }

    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override {
        if (role != Qt::DisplayRole)
            return {};
        if (orientation == Qt::Vertical)
            return section + 1;
        if (orientation == Qt::Horizontal)
            return m_header[section];
        return {};
    }

    QModelIndex index(int row, int column,
                      const QModelIndex& parent = QModelIndex()) const override {
        if (row >= m_dataVector.size() || row < 0
            || column >= m_header.size() || column < 0)
            return {};
        return createIndex(row, column);
    }

    QModelIndex parent(const QModelIndex& index) const override {
        return {};
    }

    int rowCount(const QModelIndex& parent = QModelIndex()) const override {
        return m_dataVector.size();
    }

    int columnCount(const QModelIndex& parent = QModelIndex()) const override {
        return m_header.size();
    }

    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override {
        if (!index.isValid()
            || index.row() >= m_dataVector.size() || index.row() < 0
            || index.column() >= m_header.size() || index.column() < 0)
            return {};
        if (role == Qt::DisplayRole)
            return m_dataVector[index.row()][index.column()];
        else
            return {};
    }

    void appendRow(std::vector<QString>&& rows) {
        beginInsertRows({}, m_dataVector.size(), m_dataVector.size());
        m_dataVector.push_back(std::move(rows));
        endInsertRows();
    }

    void removeOneRow() {
        beginRemoveRows({}, 0, 0);
        m_dataVector.pop_front();
        endRemoveRows();
    }

    void clear() {
        if (m_dataVector.size() == 0)
            return;
        beginRemoveRows({}, 0, m_dataVector.size() - 1);
        m_dataVector.clear();
        endRemoveRows();
    }

private:
    mydeque m_dataVector;
    const std::vector<QString> m_header;
};
