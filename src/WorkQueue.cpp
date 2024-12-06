#include <queue>
#include <mutex>
#include <condition_variable>
#include <tuple>

class WorkQueue {
private:
    std::queue<size_t> queue; // Queue of piece indices
    std::mutex mtx;
    std::condition_variable cv;

public:
    void add_piece(size_t pieceIndex) {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(pieceIndex);
        cv.notify_one();
    }

    size_t get_piece() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this]() { return !queue.empty(); });
        size_t pieceIndex = queue.front();
        queue.pop();
        return pieceIndex;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mtx);
        return queue.empty();
    }
};
