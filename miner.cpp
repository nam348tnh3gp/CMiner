#include "DSHA2.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>
#include <mutex>
#include <functional>
#include <memory>
#include <csignal>

namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono;

// ==================== FORWARD DECLARATIONS ====================
void stratumSubscribe();
void stratumAuthorize();
void stratumSubmit(uint32_t nonce);
void startFakeJobTimer();

// ==================== CẤU TRÚC BLOCK ====================
struct BlockHeader {
    uint32_t version;
    unsigned char prevBlockHash[32];
    unsigned char merkleRoot[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};

DSHA256 sha;

// ==================== THAM SỐ ====================
std::string poolHost = "stratum.slushpool.com";
int poolPort = 3333;
std::string btcAddress;
std::string walletName = "CPUMiner";

std::vector<std::pair<std::string, int>> backupPools = {
    {"stratum.slushpool.com", 3333},
    {"pool.vkbit.com", 3333},
    {"public-pool.io", 3333}
};
int currentPoolIndex = 0;

// ==================== TRẠNG THÁI ====================
std::string jobId;
uint8_t header[80];
uint8_t target[32];
std::mutex jobMutex;

std::atomic<bool> solutionFound{false};
std::atomic<bool> shouldStopMining{false};
std::atomic<uint64_t> totalHashes{0};
uint32_t bestNonce = 0;
unsigned char bestHash[32];
std::mutex submitMutex;

unsigned int numThreads;
std::vector<std::thread> threads;
std::atomic<bool> jobReceived{false};
std::atomic<bool> authorized{false};
bool useFakeJob = false;      // bật khi không có job thật
std::atomic<bool> exitFlag{false};

steady_clock::time_point startTime;
steady_clock::time_point lastReport;
uint64_t lastTotalHashes = 0;

// ==================== TCP STRATUM CLIENT (giữ nguyên) ====================
class StratumTCPClient {
public:
    using OnMessage = std::function<void(const std::string&)>;
    using OnDisconnect = std::function<void()>;
    using OnConnect = std::function<void()>;

    StratumTCPClient() : ioc_(), socket_(ioc_) {}

    void connect(const std::string& host, int port) {
        host_ = host;
        port_ = port;
        thread_ = std::thread([this]() { run(); });
    }

    void send(const std::string& msg) {
        net::post(ioc_, [this, msg]() {
            try {
                std::string line = msg + "\n";
                net::write(socket_, net::buffer(line));
            } catch (...) {}
        });
    }

    void setOnMessage(OnMessage cb) { onMessage_ = std::move(cb); }
    void setOnDisconnect(OnDisconnect cb) { onDisconnect_ = std::move(cb); }
    void setOnConnect(OnConnect cb) { onConnect_ = std::move(cb); }

    void stop() {
        net::post(ioc_, [this]() {
            try { socket_.close(); } catch (...) {}
            ioc_.stop();
        });
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        try {
            tcp::resolver resolver(ioc_);
            auto endpoints = resolver.resolve(host_, std::to_string(port_));
            net::connect(socket_, endpoints);
            std::cout << "✅ Connected (TCP) to " << host_ << ":" << port_ << std::endl;

            if (onConnect_) onConnect_();

            std::string buffer;
            while (true) {
                char data[4096];
                boost::system::error_code ec;
                size_t len = socket_.read_some(net::buffer(data), ec);
                if (ec) throw boost::system::system_error(ec);
                buffer.append(data, len);
                size_t pos;
                while ((pos = buffer.find('\n')) != std::string::npos) {
                    std::string line = buffer.substr(0, pos);
                    buffer.erase(0, pos + 1);
                    if (!line.empty()) {
                        std::cout << "[POOL] " << line << std::endl;
                        if (onMessage_) onMessage_(line);
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "❌ TCP error: " << e.what() << std::endl;
        }
        if (onDisconnect_) onDisconnect_();
    }

    net::io_context ioc_;
    tcp::socket socket_;
    std::string host_;
    int port_;
    std::thread thread_;
    OnMessage onMessage_;
    OnDisconnect onDisconnect_;
    OnConnect onConnect_;
};

std::unique_ptr<StratumTCPClient> stratumClient;

// ==================== HEX HELPERS ====================
uint8_t hexToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void hexToBytes(const std::string& hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        bytes[i] = (hexToByte(hex[i*2]) << 4) | hexToByte(hex[i*2+1]);
    }
}

void reverseBytes(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        std::swap(data[i], data[len - 1 - i]);
    }
}

bool checkTarget(const uint8_t* hash) {
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return false;
}

// ==================== STRATUM (giữ lại để gửi thử, không quan trọng) ====================
void stratumSend(const std::string& jsonStr) {
    if (stratumClient) stratumClient->send(jsonStr);
}

void stratumSubscribe() {
    json req;
    req["id"] = 1;
    req["method"] = "mining.subscribe";
    req["params"] = json::array({walletName + "/1.0"});
    std::cout << "📡 Subscribing: " << req.dump() << std::endl;
    stratumSend(req.dump());
}

void stratumAuthorize() {
    std::string user = btcAddress + "." + walletName;
    json req;
    req["id"] = 2;
    req["method"] = "mining.authorize";
    req["params"] = json::array({user, "x"});
    std::cout << "🔑 Authorizing as: " << user << std::endl;
    stratumSend(req.dump());
}

void stratumSubmit(uint32_t nonce) {
    if (useFakeJob) {
        std::cout << "🏆 [BENCHMARK] Found nonce: 0x" << std::hex << nonce << std::dec << std::endl;
        // Tạo fake job mới ngay
        startFakeJobTimer();
        return;
    }

    std::stringstream ss;
    ss << std::hex << nonce;
    json req;
    req["id"] = 4;
    req["method"] = "mining.submit";
    req["params"] = json::array({btcAddress + "." + walletName, jobId, "", "", ss.str()});
    std::cout << "🎯 Submitting nonce: 0x" << ss.str() << std::endl;
    stratumSend(req.dump());
}

// ==================== XỬ LÝ TIN NHẮN ====================
void onStratumMessage(const std::string& msg) {
    try {
        json doc = json::parse(msg);

        if (doc.contains("method") && doc["method"] == "mining.notify") {
            auto params = doc["params"];
            if (params.size() < 8) return;

            useFakeJob = false; // có job thật
            jobId = params[0].get<std::string>();
            std::string prevHashHex = params[1];
            std::string merkleHex = params[3];
            std::string versionHex = params[5];
            std::string nbitsHex = params[6];
            std::string ntimeHex = params[7];

            memset(header, 0, 80);
            hexToBytes(versionHex, header, 4);
            reverseBytes(header, 4);
            hexToBytes(prevHashHex, header + 4, 32);
            reverseBytes(header + 4, 32);
            hexToBytes(merkleHex, header + 36, 32);
            reverseBytes(header + 36, 32);
            hexToBytes(ntimeHex, header + 68, 4);
            reverseBytes(header + 68, 4);
            hexToBytes(nbitsHex, header + 72, 4);
            reverseBytes(header + 72, 4);

            uint32_t bits;
            memcpy(&bits, header + 72, 4);
            bits = __builtin_bswap32(bits);
            uint32_t exp = bits >> 24;
            uint32_t mant = bits & 0x00FFFFFF;
            memset(target, 0, 32);
            if (exp <= 32) {
                target[31 - exp] = (mant >> 16) & 0xFF;
                target[30 - exp] = (mant >> 8) & 0xFF;
                target[29 - exp] = mant & 0xFF;
            }

            solutionFound = false;
            shouldStopMining = false;
            totalHashes = 0;
            lastTotalHashes = 0;
            jobReceived = true;
            startTime = steady_clock::now();
            lastReport = startTime;
            std::cout << "📦 New job #" << jobId << " from " << poolHost << std::endl;
        }

        if (doc.contains("id") && doc["id"] == 1) {
            authorized = true;
            std::cout << "📡 Subscribe reply received" << std::endl;
            stratumAuthorize();
        }

        if (doc.contains("id") && doc["id"] == 2) {
            bool success = doc["result"].get<bool>();
            if (!success) {
                std::cerr << "❌ Auth failed" << std::endl;
                if (stratumClient) stratumClient->stop();
            } else {
                std::cout << "🔑 Authorized successfully" << std::endl;
            }
        }

        if (doc.contains("id") && doc["id"] == 4) {
            bool accepted = doc["result"].get<bool>();
            std::cout << (accepted ? "✅ Share accepted!" : "❌ Share rejected!") << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    }
}

void onStratumDisconnect() {
    std::cout << "❌ Pool disconnected" << std::endl;
    currentPoolIndex = (currentPoolIndex + 1) % backupPools.size();
    poolHost = backupPools[currentPoolIndex].first;
    poolPort = backupPools[currentPoolIndex].second;
    std::cout << "🔄 Switching to pool: " << poolHost << ":" << poolPort << std::endl;
    jobReceived = false;
    shouldStopMining = true;
    authorized = false;
    useFakeJob = false;

    // Kết nối lại và kích hoạt fake job timer mới
    stratumConnect();
}

// ==================== FAKE JOB (BENCHMARK) ====================
void startFakeJobTimer() {
    // Hủy timer cũ nếu có (không cần)
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        if (!jobReceived && !exitFlag && stratumClient) {
            std::cout << "⚠️ No real job after 10s, starting BENCHMARK mode\n";
            useFakeJob = true;

            // Tạo header và target dễ (target = 0 để tìm nonce nhanh)
            memset(header, 0x11, 76);
            header[76] = 0x00; header[77] = 0x00; header[78] = 0x00; header[79] = 0x00;
            memset(target, 0x00, 32);

            solutionFound = false;
            shouldStopMining = false;
            totalHashes = 0;
            lastTotalHashes = 0;
            jobReceived = true;
            startTime = steady_clock::now();
            lastReport = startTime;
        }
    }).detach();
}

// ==================== KẾT NỐI ====================
void stratumConnect() {
    if (btcAddress.empty()) {
        std::cerr << "⚠️ BTC address not set!" << std::endl;
        return;
    }
    if (stratumClient) {
        stratumClient->stop();
        stratumClient.reset();
    }

    stratumClient = std::make_unique<StratumTCPClient>();
    stratumClient->setOnMessage(onStratumMessage);
    stratumClient->setOnDisconnect([]() {
        // Chỉ gọi khi lỗi, không gọi lại nếu đã dừng
        if (!exitFlag) onStratumDisconnect();
    });
    stratumClient->setOnConnect([]() {
        stratumSubscribe();
        // Bắt đầu đếm ngược benchmark nếu không có job thật
        startFakeJobTimer();
    });
    stratumClient->connect(poolHost, poolPort);
}

// ==================== MINING ====================
void minerThread(int threadId) {
    BlockHeader localHeader;
    uint8_t hash[32];

    while (true) {
        if (shouldStopMining) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (!jobReceived || solutionFound) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(jobMutex);
            memcpy(&localHeader, header, 80);
        }

        uint32_t startNonce, endNonce;
        uint64_t totalNonces = 1ULL << 32;
        uint64_t noncesPerThread = totalNonces / numThreads;
        startNonce = static_cast<uint32_t>(threadId * noncesPerThread);
        endNonce = (static_cast<unsigned int>(threadId) == numThreads - 1)
                       ? UINT32_MAX
                       : static_cast<uint32_t>((static_cast<unsigned int>(threadId) + 1) * noncesPerThread) - 1;

        for (uint32_t n = startNonce; n <= endNonce && !solutionFound && !shouldStopMining; ++n) {
            localHeader.nonce = n;
            sha.hashBlockHeader((const unsigned char*)&localHeader, hash);
            totalHashes.fetch_add(1, std::memory_order_relaxed);

            if (checkTarget(hash)) {
                std::lock_guard<std::mutex> lock(submitMutex);
                if (!solutionFound) {
                    solutionFound = true;
                    bestNonce = n;
                    memcpy(bestHash, hash, 32);
                    std::cout << "🏆 BLOCK FOUND by thread " << threadId
                              << "! Nonce: 0x" << std::hex << n << std::dec << std::endl;
                }
                break;
            }
        }

        if (!solutionFound && !shouldStopMining) {
            jobReceived = false;
        }
    }
}

// ==================== BÁO CÁO ====================
void reportStats() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (shouldStopMining) continue;

        uint64_t currentTotal = totalHashes.load(std::memory_order_relaxed);
        uint64_t delta = currentTotal - lastTotalHashes;
        double elapsed = duration_cast<duration<double>>(steady_clock::now() - lastReport).count();
        double hashrate = delta / elapsed;

        std::cout << std::fixed << std::setprecision(2);
        std::cout << "⚡ " << hashrate / 1e6 << " MH/s | Total: "
                  << currentTotal << " hashes | " << (useFakeJob ? "BENCHMARK" : poolHost) << std::endl;

        lastTotalHashes = currentTotal;
        lastReport = steady_clock::now();
    }
}

// ==================== MAIN ====================
void signalHandler(int) {
    exitFlag = true;
    shouldStopMining = true;
    if (stratumClient) stratumClient->stop();
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" || arg == "--pool") {
            if (i + 1 < argc) {
                poolHost = argv[++i];
                bool found = false;
                for (auto& bp : backupPools) {
                    if (bp.first == poolHost) {
                        poolPort = bp.second;
                        found = true;
                        break;
                    }
                }
                if (!found) poolPort = 3333;
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) poolPort = std::stoi(argv[++i]);
        } else if (arg == "-a" || arg == "--address") {
            if (i + 1 < argc) btcAddress = argv[++i];
        } else if (arg == "-w" || arg == "--worker") {
            if (i + 1 < argc) walletName = argv[++i];
        } else if (arg == "-t" || arg == "--threads") {
            if (i + 1 < argc) numThreads = std::stoi(argv[++i]);
        }
    }

    if (btcAddress.empty()) {
        std::cerr << "Usage: " << argv[0]
                  << " -a <btc_address> [-o pool_host] [-p port] [-w worker] [-t threads]\n";
        return 1;
    }

    numThreads = (numThreads > 0) ? numThreads : std::thread::hardware_concurrency();
    std::cout << "🚀 Starting BTC Miner CLI (auto benchmarks if no pool)\n";
    std::cout << "   Pool: " << poolHost << ":" << poolPort << "\n";
    std::cout << "   Address: " << btcAddress << "\n";
    std::cout << "   Worker: " << walletName << "\n";
    std::cout << "   Threads: " << numThreads << "\n\n";

    stratumConnect();

    for (unsigned int i = 0; i < numThreads; ++i) {
        threads.emplace_back(minerThread, static_cast<int>(i));
    }

    std::thread(reportStats).detach();

    while (!exitFlag) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (solutionFound) {
            stratumSubmit(bestNonce);
            solutionFound = false;
            if (useFakeJob) {
                // Bắt đầu fake job mới
                startFakeJobTimer();
            } else {
                jobReceived = false;
                shouldStopMining = true;
            }
        }

        if (!stratumClient && !btcAddress.empty() && !exitFlag) {
            static auto lastReconnect = steady_clock::now();
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - lastReconnect).count() > 10) {
                lastReconnect = now;
                std::cout << "🔄 Reconnecting..." << std::endl;
                stratumConnect();
            }
        }
    }

    shouldStopMining = true;
    if (stratumClient) stratumClient->stop();
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    std::cout << "👋 Miner stopped." << std::endl;
    return 0;
}
