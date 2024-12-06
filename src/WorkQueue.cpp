#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include <future>
#include <iostream>
#include <algorithm>

// Thread-safe work queue for managing piece downloads
class WorkQueue {
private:
    std::queue<size_t> pieces;
    std::mutex mtx;

public:
    void add_piece(size_t pieceIndex) {
        std::lock_guard<std::mutex> lock(mtx);
        pieces.push(pieceIndex);
    }

    std::optional<size_t> get_piece() {
        std::lock_guard<std::mutex> lock(mtx);
        if (pieces.empty()) {
            return std::nullopt;
        }
        size_t piece = pieces.front();
        pieces.pop();
        return piece;
    }
};