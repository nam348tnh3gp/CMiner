#include "DSHA2.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>

// Cấu trúc block header 80 byte
struct BlockHeader {
    uint32_t version;
    unsigned char prevBlockHash[32];
    unsigned char merkleRoot[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};

// Kiểm tra xem hash có bắt đầu bằng ít nhất 'difficulty' byte 0x00 không
bool isValidHash(const unsigned char hash[32], int difficulty) {
    for (int i = 0; i < difficulty; i++) {
        if (hash[i] != 0x00) return false;
    }
    return true;
}

// Biến toàn cục dùng để dừng các luồng khi tìm thấy
std::atomic<bool> found{false};
std::atomic<uint64_t> totalHashes{0};
uint32_t bestNonce = 0;
unsigned char bestHash[32];

// Hàm đào của một luồng
void minerThread(BlockHeader baseHeader, uint32_t startNonce, uint32_t endNonce, int difficulty) {
    DSHA256 sha;
    BlockHeader hdr = baseHeader;
    unsigned char hash[32];
    for (uint32_t nonce = startNonce; nonce < endNonce; nonce++) {
        if (found.load(std::memory_order_relaxed)) break;
        hdr.nonce = nonce;
        sha.hashBlockHeader(reinterpret_cast<const unsigned char*>(&hdr), hash);
        totalHashes.fetch_add(1, std::memory_order_relaxed);
        if (isValidHash(hash, difficulty)) {
            bool expected = false;
            if (found.compare_exchange_strong(expected, true)) {
                bestNonce = nonce;
                memcpy(bestHash, hash, 32);
            }
            break;
        }
    }
}

int main() {
    // Thiết lập block header giả
    BlockHeader baseHeader;
    baseHeader.version = 0x20000000; // version 2
    // previous block hash (giả)
    memset(baseHeader.prevBlockHash, 0xAB, 32);
    // merkle root (giả)
    memset(baseHeader.merkleRoot, 0xCD, 32);
    baseHeader.timestamp = static_cast<uint32_t>(std::time(nullptr));
    baseHeader.bits = 0x1d00ffff; // target difficulty (ví dụ)
    baseHeader.nonce = 0;

    int difficulty = 4; // yêu cầu 4 byte 0 ở đầu hash (có thể thay đổi 4->5 để khó hơn)
    std::cout << "Bat dau dao voi difficulty " << difficulty << " byte zero...\n";
    std::cout << "Header: version=0x" << std::hex << baseHeader.version
              << " timestamp=0x" << baseHeader.timestamp << "\n";

    // Số luồng bằng số nhân CPU
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;
    std::cout << "Su dung " << numThreads << " luong\n";

    // Chia không gian nonce 32-bit cho các luồng
    uint64_t totalNonces = 1ULL << 32;
    uint64_t noncesPerThread = totalNonces / numThreads;

    std::vector<std::thread> threads;
    auto startTime = std::chrono::steady_clock::now();

    for (unsigned int i = 0; i < numThreads; i++) {
        uint32_t start = static_cast<uint32_t>(i * noncesPerThread);
        uint32_t end = (i == numThreads - 1) ? UINT32_MAX : static_cast<uint32_t>((i + 1) * noncesPerThread);
        threads.emplace_back(minerThread, baseHeader, start, end, difficulty);
    }

    // Hiển thị hashrate mỗi giây trong khi chờ
    uint64_t lastTotal = 0;
    while (!found) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t currentTotal = totalHashes.load(std::memory_order_relaxed);
        double hashrate = (currentTotal - lastTotal) / 1e6; // MH/s
        std::cout << "[Status] " << std::dec << currentTotal << " hashes, hashrate " << hashrate << " MH/s\n";
        lastTotal = currentTotal;
    }

    auto endTime = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;

    // Dừng tất cả các luồng
    for (auto &t : threads) {
        if (t.joinable()) t.join();
    }

    // In kết quả
    std::cout << "\n=================================\n";
    std::cout << "DAO THANH CONG!\n";
    std::cout << "Nonce: " << std::dec << bestNonce << " (0x" << std::hex << bestNonce << ")\n";
    std::cout << "Hash: ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bestHash[i];
    }
    std::cout << std::dec << "\n";
    std::cout << "Thoi gian: " << elapsed.count() << " giay\n";
    std::cout << "Tong so hash: " << totalHashes.load() << "\n";
    std::cout << "Toc do trung binh: " << (totalHashes.load() / elapsed.count() / 1e6) << " MH/s\n";

    return 0;
}
