// miner.cpp - Stratum CPU Miner (SHA-256) dựa trên cpuminer-opt
// Biên dịch: g++ -O3 -march=native -pthread miner.cpp -lboost_system -o miner

#include "DSHA2.h"
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>
#include <mutex>
#include <functional>
#include <memory>
#include <csignal>
#include <random>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono;

// --------------------- LƯU JOB GỐC ---------------------
struct RawJob {
    std::string jobId;
    std::string prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<std::string> merkleBranch;
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean;
};
static RawJob g_rawJob;
static std::mutex g_rawJobMutex;

// --------------------- CẤU TRÚC WORK ---------------------
struct Work {
    std::string jobId;
    uint32_t nbits;
    uint8_t target[32];
    double difficulty;
    bool clean;
};
static std::atomic<bool> g_haveWork{false};
static Work g_work;
static std::mutex g_workMutex;

// --------------------- TRẠNG THÁI TOÀN CỤC ---------------------
static std::atomic<bool> g_stop{false};
static std::string g_poolHost = "stratum.slushpool.com";
static int g_poolPort = 3333;
static std::string g_user;
static std::string g_pass = "x";
static unsigned int g_numThreads = 0;

static std::string g_extranonce1;
static size_t g_extranonce2_size = 4;
static std::atomic<uint64_t> g_extranonce2_base{0};

static std::atomic<uint64_t> g_totalHashes{0};
static steady_clock::time_point g_lastReportTime;
static uint64_t g_lastTotalHashes = 0;

static std::unique_ptr<tcp::socket> g_socket;
static std::unique_ptr<asio::io_context> g_ioc;
static std::unique_ptr<asio::steady_timer> g_pingTimer;
static std::thread g_ioThread;
static std::thread g_statsThread;
static std::vector<std::thread> g_minerThreads;

// --------------------- HEX UTILS ---------------------
static inline uint8_t hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
static std::string hexToBin(const std::string& hex) {
    std::string bin(hex.size() / 2, 0);
    for (size_t i = 0; i < bin.size(); i++)
        bin[i] = (hexCharToByte(hex[i*2]) << 4) | hexCharToByte(hex[i*2+1]);
    return bin;
}
static std::string binToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
        ss << std::setw(2) << (int)data[i];
    return ss.str();
}
static void reverseBytes(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len/2; i++) std::swap(data[i], data[len-1-i]);
}

// --------------------- XÂY DỰNG HEADER ---------------------
static bool buildHeaderFromRawJob(const RawJob& job, uint64_t extranonce2, uint8_t header[80]) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(g_extranonce2_size * 2) << extranonce2;
    std::string extranonce2_hex = ss.str();
    std::string coinbaseHex = job.coinb1 + g_extranonce1 + extranonce2_hex + job.coinb2;
    std::string coinbaseBin = hexToBin(coinbaseHex);

    DSHA256 ctx;
    ctx.reset();
    ctx.write((const unsigned char*)coinbaseBin.data(), coinbaseBin.size());
    unsigned char merkleRoot[32];
    ctx.finalize(merkleRoot);

    for (const auto& branch : job.merkleBranch) {
        std::string branchBin = hexToBin(branch);
        unsigned char combined[64];
        memcpy(combined, merkleRoot, 32);
        memcpy(combined+32, branchBin.data(), 32);
        ctx.reset();
        ctx.write(combined, 64);
        ctx.finalize(merkleRoot);
    }

    memset(header, 0, 80);
    uint32_t ver = std::stoul(job.version, nullptr, 16);
    ver = __builtin_bswap32(ver);
    memcpy(header, &ver, 4);

    std::string prevBin = hexToBin(job.prevhash);
    reverseBytes((uint8_t*)prevBin.data(), 32);
    memcpy(header+4, prevBin.data(), 32);

    reverseBytes(merkleRoot, 32);
    memcpy(header+36, merkleRoot, 32);

    uint32_t ntimeVal = std::stoul(job.ntime, nullptr, 16);
    ntimeVal = __builtin_bswap32(ntimeVal);
    memcpy(header+68, &ntimeVal, 4);

    uint32_t nbitsVal = std::stoul(job.nbits, nullptr, 16);
    nbitsVal = __builtin_bswap32(nbitsVal);
    memcpy(header+72, &nbitsVal, 4);

    return true;
}

// --------------------- CẬP NHẬT WORK ---------------------
static void updateWorkFromRawJob(const RawJob& job) {
    Work newWork;
    newWork.jobId = job.jobId;
    newWork.nbits = std::stoul(job.nbits, nullptr, 16);
    newWork.clean = job.clean;
    uint32_t exp = newWork.nbits >> 24;
    uint32_t mant = newWork.nbits & 0x00FFFFFF;
    memset(newWork.target, 0, 32);
    if (exp <= 32) {
        int shift = 32 - exp;
        newWork.target[shift]   = (mant >> 16) & 0xFF;
        newWork.target[shift+1] = (mant >> 8) & 0xFF;
        newWork.target[shift+2] = mant & 0xFF;
    }
    newWork.difficulty = (double)0xFFFF000000000000ULL / (double)(newWork.nbits ? newWork.nbits : 1);
    {
        std::lock_guard<std::mutex> lock(g_workMutex);
        g_work = newWork;
        g_haveWork = true;
        if (job.clean) g_extranonce2_base = 0;
    }
    std::cout << "[JOB] New work #" << newWork.jobId << " diff=" << newWork.difficulty << "\n";
}

// --------------------- GỬI TIN NHẮN (BÂY GIỜ POST QUA IO_CONTEXT) ---------------------
static void sendStratum(const std::string& msg) {
    if (!g_ioc) return;
    // Post công việc gửi vào io_context để chạy trên luồng ioThread
    asio::post(*g_ioc, [msg]() {
        if (!g_socket || !g_socket->is_open()) return;
        try {
            asio::write(*g_socket, asio::buffer(msg + "\n"));
        } catch (...) {}
    });
}

static void sendSubscribe() {
    json req; req["id"] = 1; req["method"] = "mining.subscribe"; req["params"] = {"cpuminer/2.0.0"};
    sendStratum(req.dump()); std::cout << "[STRATUM] Subscribe sent\n";
}
static void sendAuthorize() {
    json req; req["id"] = 2; req["method"] = "mining.authorize"; req["params"] = {g_user, g_pass};
    sendStratum(req.dump()); std::cout << "[STRATUM] Authorize sent for " << g_user << "\n";
}
static void sendPing() {
    json req; req["id"] = 0; req["method"] = "mining.ping";
    sendStratum(req.dump()); std::cout << "[STRATUM] Ping sent\n";
}

// --------------------- XỬ LÝ TIN NHẮN ---------------------
static void processStratumMessage(const std::string& line) {
    try {
        json msg = json::parse(line);
        if (msg.contains("method") && msg["method"] == "mining.notify") {
            auto p = msg["params"];
            if (p.size() < 9) return;
            RawJob job;
            job.jobId = p[0].get<std::string>();
            job.prevhash = p[1].get<std::string>();
            job.coinb1 = p[2].get<std::string>();
            job.coinb2 = p[3].get<std::string>();
            for (auto& branch : p[4]) job.merkleBranch.push_back(branch.get<std::string>());
            job.version = p[5].get<std::string>();
            job.nbits = p[6].get<std::string>();
            job.ntime = p[7].get<std::string>();
            job.clean = p[8].get<bool>();
            {
                std::lock_guard<std::mutex> lock(g_rawJobMutex);
                g_rawJob = job;
            }
            updateWorkFromRawJob(job);
            return;
        }
        if (msg.contains("method") && msg["method"] == "mining.set_difficulty") {
            std::cout << "[DIFF] Difficulty set to " << msg["params"][0].get<double>() << "\n";
            return;
        }
        if (msg.contains("method") && msg["method"] == "mining.set_extranonce") {
            g_extranonce1 = msg["params"][0].get<std::string>();
            g_extranonce2_size = msg["params"][1].get<int>();
            std::cout << "[EXTRANONCE] Set: " << g_extranonce1 << " size=" << g_extranonce2_size << "\n";
            return;
        }
        if (msg.contains("id") && msg["id"] == 1 && msg.contains("result")) {
            auto res = msg["result"];
            if (res.is_array() && res.size() >= 2) {
                g_extranonce1 = res[1].get<std::string>();
                g_extranonce2_size = res[2].get<int>();
                std::cout << "[SUBSCRIBE] OK, extranonce1=" << g_extranonce1 << " size=" << g_extranonce2_size << "\n";
                sendAuthorize();
            }
            return;
        }
        if (msg.contains("id") && msg["id"] == 2) {
            if (msg["result"].get<bool>()) std::cout << "[AUTH] Authorized successfully\n";
            else std::cerr << "[AUTH] FAILED!\n";
            return;
        }
        if (msg.contains("id") && msg["id"] == 4) {
            bool accepted = msg["result"].get<bool>();
            if (accepted) std::cout << "[SHARE] ACCEPTED\n";
            else std::cout << "[SHARE] REJECTED: " << msg["error"].dump() << "\n";
            return;
        }
        if (msg.contains("id") && msg["id"] == 0 && msg.contains("result")) return; // pong
        std::cout << "[POOL] " << msg.dump() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[PARSE] Error: " << e.what() << " | line: " << line << "\n";
    }
}

// --------------------- PING HANDLER (ASYNC) ---------------------
static void pingHandler(const boost::system::error_code& ec) {
    if (!ec && !g_stop && g_socket && g_socket->is_open()) {
        sendPing();
        if (g_pingTimer) {
            g_pingTimer->expires_after(seconds(30));
            g_pingTimer->async_wait(pingHandler);
        }
    }
}

// --------------------- ĐỌC DỮ LIỆU BẤT ĐỒNG BỘ ---------------------
static void doAsyncRead(std::shared_ptr<asio::streambuf> buf) {
    asio::async_read_until(*g_socket, *buf, '\n',
        [buf](const boost::system::error_code& ec, size_t /*length*/) {
            if (!ec && !g_stop) {
                std::istream is(buf.get());
                std::string line;
                while (std::getline(is, line)) {
                    if (!line.empty()) processStratumMessage(line);
                }
                doAsyncRead(buf); // Đọc tiếp dòng sau
            } else if (ec != asio::error::operation_aborted) {
                std::cerr << "[NET] Read error: " << ec.message() << "\n";
                // Có thể báo lỗi để kết nối lại
            }
        });
}

// --------------------- LUỒNG MẠNG (SỬ DỤNG ASYNC IO) ---------------------
static void ioThreadFunc() {
    while (!g_stop) {
        try {
            g_ioc = std::make_unique<asio::io_context>();
            tcp::resolver resolver(*g_ioc);
            auto endpoints = resolver.resolve(g_poolHost, std::to_string(g_poolPort));
            g_socket = std::make_unique<tcp::socket>(*g_ioc);
            asio::connect(*g_socket, endpoints);
            std::cout << "[NET] Connected to " << g_poolHost << ":" << g_poolPort << std::endl;

            sendSubscribe();

            g_pingTimer = std::make_unique<asio::steady_timer>(*g_ioc);
            g_pingTimer->expires_after(seconds(30));
            g_pingTimer->async_wait(pingHandler);

            auto buf = std::make_shared<asio::streambuf>();
            doAsyncRead(buf);

            g_ioc->run(); // Chạy event loop

        } catch (const std::exception& e) {
            std::cerr << "[NET] Error: " << e.what() << ". Reconnecting in 5s...\n";
        }
        g_socket.reset();
        g_pingTimer.reset();
        g_ioc.reset();
        if (!g_stop) std::this_thread::sleep_for(seconds(5));
    }
}

// --------------------- THỐNG KÊ ---------------------
static void statsThreadFunc() {
    g_lastReportTime = steady_clock::now();
    g_lastTotalHashes = 0;
    while (!g_stop) {
        std::this_thread::sleep_for(seconds(2));
        uint64_t cur = g_totalHashes.load();
        double elapsed = duration<double>(steady_clock::now() - g_lastReportTime).count();
        double rate = (cur - g_lastTotalHashes) / elapsed;
        std::cout << std::fixed << std::setprecision(2)
                  << "[STATS] " << rate / 1e6 << " MH/s | Total: " << cur << "\n";
        g_lastTotalHashes = cur;
        g_lastReportTime = steady_clock::now();
    }
}

// --------------------- MINER THREAD ---------------------
static void minerThreadFunc(int threadId) {
    DSHA256 shaCtx;
    uint8_t hash[32], header[80];
    uint32_t nonce;

    while (!g_stop) {
        while (!g_haveWork && !g_stop) std::this_thread::sleep_for(milliseconds(10));
        if (g_stop) break;

        RawJob rawJob;
        Work work;
        {
            std::lock_guard<std::mutex> lock(g_rawJobMutex);
            rawJob = g_rawJob;
        }
        {
            std::lock_guard<std::mutex> lock(g_workMutex);
            work = g_work;
        }

        uint64_t myExtNonce2 = g_extranonce2_base.fetch_add(1);
        if (!buildHeaderFromRawJob(rawJob, myExtNonce2, header)) continue;

        const uint32_t STEP = 65536;
        uint32_t start = threadId * STEP;
        uint32_t end = start + STEP - 1;

        for (nonce = start; nonce < end && !g_stop; ++nonce) {
            uint32_t nonce_le = __builtin_bswap32(nonce);
            memcpy(header + 76, &nonce_le, 4);
            shaCtx.hashBlockHeader(header, hash);
            g_totalHashes++;

            bool ok = true;
            for (int i = 0; i < 32; i++) {
                if (hash[i] < work.target[i]) break;
                if (hash[i] > work.target[i]) { ok = false; break; }
            }
            if (ok) {
                json submit;
                submit["id"] = 4;
                submit["method"] = "mining.submit";
                submit["params"] = {g_user, work.jobId,
                                    binToHex((uint8_t*)&myExtNonce2, g_extranonce2_size),
                                    rawJob.ntime,
                                    binToHex((uint8_t*)&nonce, 4)};
                sendStratum(submit.dump());
                std::cout << "[FOUND] Thread " << threadId << " nonce=0x" << std::hex << nonce << std::dec << "\n";
                break;
            }
        }
    }
}

// --------------------- MAIN ---------------------
static void signalHandler(int) { g_stop = true; }

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::string btcAddress;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" && i+1 < argc) g_poolHost = argv[++i];
        else if (arg == "-p" && i+1 < argc) g_poolPort = std::stoi(argv[++i]);
        else if (arg == "-a" && i+1 < argc) btcAddress = argv[++i];
        else if (arg == "-w" && i+1 < argc) g_user = btcAddress + "." + argv[++i];
        else if (arg == "-t" && i+1 < argc) g_numThreads = std::stoul(argv[++i]);
    }
    if (btcAddress.empty() || g_user.empty()) {
        std::cerr << "Usage: " << argv[0] << " -a BTC_ADDRESS -w WORKER_NAME [-o pool] [-p port] [-t threads]\n";
        return 1;
    }
    if (g_numThreads == 0) g_numThreads = std::thread::hardware_concurrency();

    std::cout << "=== Stratum CPU Miner (SHA-256) ===\n"
              << "Pool: " << g_poolHost << ":" << g_poolPort << "\n"
              << "User: " << g_user << "\n"
              << "Threads: " << g_numThreads << "\n\n";

    g_ioThread = std::thread(ioThreadFunc);
    g_statsThread = std::thread(statsThreadFunc);
    for (unsigned i = 0; i < g_numThreads; i++)
        g_minerThreads.emplace_back(minerThreadFunc, i);

    while (!g_stop) std::this_thread::sleep_for(milliseconds(100));
    if (g_ioc) g_ioc->stop(); // Dừng io_context
    g_ioThread.join(); g_statsThread.join();
    for (auto& t : g_minerThreads) t.join();

    std::cout << "Miner stopped.\n";
    return 0;
}
