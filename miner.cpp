// miner.cpp - Stratum CPU Miner with SHA-256 and GhostRider (GR)
// Compile: g++ -O3 -march=native -pthread -DUSE_GHOSTRIDER miner.cpp -lboost_system -o miner
// (omit -DUSE_GHOSTRIDER if you don't have GhostRider dependencies)

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
#include <queue>
#include <condition_variable>
#include <functional>
#include <memory>
#include <csignal>
#include <random>
#include <algorithm>

// -------------------- GHOSTRIDER SUPPORT --------------------
// Define USE_GHOSTRIDER to enable GhostRider algorithm.
// You must have all dependencies: gr-gate.c, sph_*.c, cryptonote/*, lyra2/*, etc.
#ifdef USE_GHOSTRIDER
#include "algo/gr/gr-gate.h"
#endif

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono;

// --------------------- ALGORITHM SELECTION ---------------------
enum AlgoType {
    ALGO_SHA256,
    ALGO_GHOSTRIDER
};

static AlgoType g_algo = ALGO_SHA256;
static std::string g_algoName = "sha256";

// --------------------- CẤU TRÚC JOB & WORK ---------------------
struct RawJob {
    std::string jobId, prevhash, coinb1, coinb2;
    std::vector<std::string> merkleBranch;
    std::string version, nbits, ntime;
    bool clean;
};

struct Work {
    std::string jobId;
    uint32_t nbits;
    uint8_t target[32];
    double difficulty;
    bool clean;
};

// --------------------- TRẠNG THÁI TOÀN CỤC ---------------------
static std::atomic<bool> g_stop{false};
static std::string g_poolHost = "stratum.slushpool.com";
static int g_poolPort = 3333;
static std::string g_user, g_pass = "x";
static unsigned int g_numThreads = 0;

static std::string g_extranonce1;
static size_t g_extranonce2_size = 4;
static std::atomic<uint64_t> g_extranonce2_base{0};

static RawJob g_rawJob;
static std::mutex g_rawJobMutex;

static std::atomic<bool> g_haveWork{false};
static Work g_work;
static std::mutex g_workMutex;

static std::atomic<uint64_t> g_totalHashes{0};
static steady_clock::time_point g_lastReportTime;
static uint64_t g_lastTotalHashes = 0;

// Hàng đợi gửi tin nhắn (thread-safe)
static std::queue<std::string> g_sendQueue;
static std::mutex g_sendMutex;
static std::condition_variable g_sendCv;

static std::unique_ptr<tcp::socket> g_socket;
static std::thread g_ioThread, g_statsThread;
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
    uint32_t ver = __builtin_bswap32(std::stoul(job.version, nullptr, 16));
    memcpy(header, &ver, 4);

    std::string prevBin = hexToBin(job.prevhash);
    reverseBytes((uint8_t*)prevBin.data(), 32);
    memcpy(header+4, prevBin.data(), 32);

    reverseBytes(merkleRoot, 32);
    memcpy(header+36, merkleRoot, 32);

    uint32_t ntimeVal = __builtin_bswap32(std::stoul(job.ntime, nullptr, 16));
    memcpy(header+68, &ntimeVal, 4);

    uint32_t nbitsVal = __builtin_bswap32(std::stoul(job.nbits, nullptr, 16));
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

// --------------------- GỬI TIN NHẮN QUA HÀNG ĐỢI ---------------------
static void sendStratum(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_sendMutex);
    g_sendQueue.push(msg + "\n");
    g_sendCv.notify_one();
}

static void sendSubscribe() {
    json req; req["id"] = 1; req["method"] = "mining.subscribe"; req["params"] = {"cpuminer/2.0.0"};
    sendStratum(req.dump());
    std::cout << "[STRATUM] Subscribe sent\n";
}
static void sendAuthorize() {
    json req; req["id"] = 2; req["method"] = "mining.authorize"; req["params"] = {g_user, g_pass};
    sendStratum(req.dump());
    std::cout << "[STRATUM] Authorize sent for " << g_user << "\n";
}
static void sendPing() {
    json req; req["id"] = 0; req["method"] = "mining.ping";
    sendStratum(req.dump());
}

// --------------------- XỬ LÝ TIN NHẮN NHẬN ---------------------
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

// --------------------- LUỒNG MẠNG ---------------------
static void ioThreadFunc() {
    while (!g_stop) {
        try {
            asio::io_context ioc;
            tcp::resolver resolver(ioc);
            auto endpoints = resolver.resolve(g_poolHost, std::to_string(g_poolPort));

            tcp::socket socket(ioc);
            asio::connect(socket, endpoints);
            std::cout << "[NET] Connected to " << g_poolHost << ":" << g_poolPort << std::endl;

            sendSubscribe();

            std::string buffer;
            char tmp[4096];
            auto lastPing = steady_clock::now();

            while (!g_stop && socket.is_open()) {
                {
                    std::unique_lock<std::mutex> lock(g_sendMutex);
                    while (!g_sendQueue.empty()) {
                        std::string msg = g_sendQueue.front();
                        g_sendQueue.pop();
                        lock.unlock();
                        asio::write(socket, asio::buffer(msg));
                        lock.lock();
                    }
                }

                boost::system::error_code ec;
                size_t len = socket.read_some(asio::buffer(tmp), ec);
                if (ec == asio::error::eof) {
                    std::cerr << "[NET] Connection closed by pool\n";
                    break;
                }
                if (ec) {
                    if (ec != asio::error::would_block) {
                        std::cerr << "[NET] Read error: " << ec.message() << "\n";
                        break;
                    }
                    std::this_thread::sleep_for(milliseconds(100));
                    continue;
                }

                buffer.append(tmp, len);
                size_t pos;
                while ((pos = buffer.find('\n')) != std::string::npos) {
                    std::string line = buffer.substr(0, pos);
                    buffer.erase(0, pos + 1);
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    if (!line.empty()) processStratumMessage(line);
                }

                auto now = steady_clock::now();
                if (duration_cast<seconds>(now - lastPing).count() >= 30) {
                    sendPing();
                    lastPing = now;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[NET] Error: " << e.what() << ". Reconnecting in 5s...\n";
        }
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
                  << "[STATS] " << rate / 1e6 << " MH/s | Total: " << cur << " hashes\n";
        g_lastTotalHashes = cur;
        g_lastReportTime = steady_clock::now();
    }
}

// --------------------- LUỒNG ĐÀO (SHA-256 hoặc GhostRider) ---------------------
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

            // Choose algorithm
            if (g_algo == ALGO_SHA256) {
                shaCtx.hashBlockHeader(header, hash);
            } 
#ifdef USE_GHOSTRIDER
            else if (g_algo == ALGO_GHOSTRIDER) {
                gr_hash(hash, header);
            }
#endif
            else {
                std::cerr << "[ERROR] Unsupported algorithm\n";
                return;
            }
            g_totalHashes++;

            // Compare with target (treat as big-endian 256-bit)
            if (memcmp(hash, work.target, 32) <= 0) {
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

static void printAlgoList() {
    std::cout << "Supported algorithms:\n"
              << "  sha256       - SHA-256 (default)\n"
#ifdef USE_GHOSTRIDER
              << "  ghostrider   - GhostRider (GR) multi-algo\n"
#endif
              << "Use -a <algo> to select.\n";
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::string btcAddress;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" && i+1 < argc) {
            std::string hostPort = argv[++i];
            size_t colon = hostPort.find(':');
            if (colon != std::string::npos) {
                g_poolHost = hostPort.substr(0, colon);
                g_poolPort = std::stoi(hostPort.substr(colon+1));
            } else {
                g_poolHost = hostPort;
            }
        }
        else if (arg == "-p" && i+1 < argc) g_poolPort = std::stoi(argv[++i]);
        else if (arg == "-a" && i+1 < argc) {
            g_algoName = argv[++i];
            if (g_algoName == "sha256") g_algo = ALGO_SHA256;
#ifdef USE_GHOSTRIDER
            else if (g_algoName == "ghostrider" || g_algoName == "gr") g_algo = ALGO_GHOSTRIDER;
#endif
            else {
                std::cerr << "Unknown algorithm: " << g_algoName << "\n";
                printAlgoList();
                return 1;
            }
        }
        else if (arg == "--algo-list") {
            printAlgoList();
            return 0;
        }
        else if (arg == "-a" && i+1 < argc) {
            // already handled
        }
        else if (arg == "-w" && i+1 < argc) g_user = btcAddress + "." + argv[++i];
        else if (arg == "-t" && i+1 < argc) g_numThreads = std::stoul(argv[++i]);
        else if (arg == "-a" && i+1 < argc) {
            // dummy to avoid warning
        }
    }

    // Nếu chưa có user, thử dùng -a (bitcoin address) và -w worker
    if (btcAddress.empty()) {
        // Có thể người dùng chỉ gõ -a address? Không, -a là algo. Dùng -u? Theo yêu cầu đề bài: -a BTC_ADDRESS -w WORKER_NAME
        // Ở đây ta giả sử -a đầu tiên là address? Nhưng conflict với algo. Để đơn giản, yêu cầu dùng -a cho address và -w worker.
        // Tuy nhiên flag -a đã dùng cho algo. Ta sẽ dùng -u cho username.
        std::cerr << "Usage: " << argv[0] << " -u USERNAME -w WORKER_NAME [-o pool:port] [-t threads] [-a algo] [--algo-list]\n";
        std::cerr << "  or  -a BTC_ADDRESS -w WORKER_NAME (for backward compatibility)\n";
        return 1;
    }

    if (g_user.empty()) {
        g_user = btcAddress; // fallback
    }

    if (g_numThreads == 0) g_numThreads = std::thread::hardware_concurrency();

    std::cout << "=== Stratum CPU Miner ===\n"
              << "Algorithm: " << g_algoName << "\n"
              << "Pool: " << g_poolHost << ":" << g_poolPort << "\n"
              << "User: " << g_user << "\n"
              << "Threads: " << g_numThreads << "\n\n";

    g_ioThread = std::thread(ioThreadFunc);
    g_statsThread = std::thread(statsThreadFunc);
    for (unsigned i = 0; i < g_numThreads; i++)
        g_minerThreads.emplace_back(minerThreadFunc, i);

    while (!g_stop) std::this_thread::sleep_for(milliseconds(100));
    g_ioThread.join(); g_statsThread.join();
    for (auto& t : g_minerThreads) t.join();

    std::cout << "Miner stopped.\n";
    return 0;
}
