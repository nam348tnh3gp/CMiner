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
#include <cassert>

namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono;

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

// ==================== HÀM HASH ====================
// Double SHA-256 dùng DSHA256 (dữ liệu tùy ý)
void doubleSHA256(const uint8_t* data, size_t len, uint8_t* out) {
    uint8_t tmp[32];
    DSHA256 ctx;
    ctx.reset();
    ctx.write(data, len);
    ctx.finalize(tmp);
    ctx.reset();
    ctx.write(tmp, 32);
    ctx.finalize(out);
}

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

// ==================== TRẠNG THÁI STRATUM ====================
struct StratumJob {
    std::string job_id;
    std::string prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<std::string> merkle_branch;
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean;
};

StratumJob currentJob;
std::mutex jobMutex;
std::string extranonce1;
size_t extranonce2_size = 0;
uint32_t extranonce2_counter = 0;

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

steady_clock::time_point startTime;
steady_clock::time_point lastReport;
uint64_t lastTotalHashes = 0;

// ==================== TCP CLIENT ====================
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
static uint8_t hexToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hexToBytes(const std::string& hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++)
        out[i] = (hexToByte(hex[i*2]) << 4) | hexToByte(hex[i*2+1]);
}

static std::string bin2hex(const uint8_t* bin, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
        ss << std::setw(2) << static_cast<int>(bin[i]);
    return ss.str();
}

static void reverseBytes(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len / 2; i++)
        std::swap(data[i], data[len - 1 - i]);
}

// ==================== STRATUM GỬI LỆNH ====================
void stratumSend(const std::string& jsonStr) {
    if (stratumClient) stratumClient->send(jsonStr);
}

void stratumSubscribe() {
    json req;
    req["id"] = 1;
    req["method"] = "mining.subscribe";
    req["params"] = json::array({walletName + "/1.0"});
    std::cout << "📡 Subscribing..." << std::endl;
    stratumSend(req.dump());
}

void stratumAuthorize() {
    std::string user = btcAddress + "." + walletName;
    json req;
    req["id"] = 2;
    req["method"] = "mining.authorize";
    req["params"] = json::array({user, "x"});
    std::cout << "🔑 Authorizing as " << user << std::endl;
    stratumSend(req.dump());
}

void stratumSubmit(uint32_t nonce, const std::string& ntime, const std::string& extranonce2) {
    json req;
    req["id"] = 4;
    req["method"] = "mining.submit";
    req["params"] = json::array({btcAddress + "." + walletName, currentJob.job_id, extranonce2, ntime, bin2hex((uint8_t*)&nonce, 4)});
    std::cout << "🎯 Submitting nonce: 0x" << std::hex << nonce << std::dec << std::endl;
    stratumSend(req.dump());
}

// ==================== XỬ LÝ TIN NHẮN ====================
void onStratumMessage(const std::string& msg) {
    try {
        json doc = json::parse(msg);

        if (doc.contains("id") && doc["id"] == 1 && doc.contains("result")) {
            auto result = doc["result"];
            if (result.is_array() && result.size() >= 2) {
                extranonce1 = result[1].get<std::string>();
                extranonce2_size = result[2].get<int>();
                std::cout << "📡 Subscribed, extranonce1=" << extranonce1 << ", extranonce2_size=" << extranonce2_size << std::endl;
                stratumAuthorize();
            }
            return;
        }

        if (doc.contains("id") && doc["id"] == 2) {
            if (doc["result"].get<bool>()) {
                authorized = true;
                std::cout << "🔑 Authorized successfully" << std::endl;
            } else {
                std::cerr << "❌ Auth failed" << std::endl;
                if (stratumClient) stratumClient->stop();
            }
            return;
        }

        if (doc.contains("id") && doc["id"] == 4) {
            bool accepted = doc["result"].get<bool>();
            std::cout << (accepted ? "✅ Share accepted!" : "❌ Share rejected!") << std::endl;
            return;
        }

        if (doc.contains("method") && doc["method"] == "mining.notify") {
            auto params = doc["params"];
            if (params.size() < 9) return;

            StratumJob newJob;
            newJob.job_id = params[0].get<std::string>();
            newJob.prevhash = params[1].get<std::string>();
            newJob.coinb1 = params[2].get<std::string>();
            newJob.coinb2 = params[3].get<std::string>();
            auto merkle = params[4];
            if (merkle.is_array())
                for (auto& item : merkle)
                    newJob.merkle_branch.push_back(item.get<std::string>());
            newJob.version = params[5].get<std::string>();
            newJob.nbits = params[6].get<std::string>();
            newJob.ntime = params[7].get<std::string>();
            newJob.clean = params[8].get<bool>();

            {
                std::lock_guard<std::mutex> lock(jobMutex);
                currentJob = newJob;
                extranonce2_counter = 0;
            }

            solutionFound = false;
            shouldStopMining = false;
            totalHashes = 0;
            lastTotalHashes = 0;
            jobReceived = true;
            startTime = steady_clock::now();
            lastReport = startTime;
            std::cout << "📦 New job #" << currentJob.job_id << " from " << poolHost << std::endl;
            return;
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
    stratumClient->setOnDisconnect([]() { onStratumDisconnect(); });
    stratumClient->setOnConnect([]() { stratumSubscribe(); });
    stratumClient->connect(poolHost, poolPort);
}

// ==================== MERKLE ROOT ====================
std::string buildMerkleRoot(const StratumJob& job, const std::string& extranonce2) {
    std::string coinbase = job.coinb1 + extranonce1 + extranonce2 + job.coinb2;
    std::vector<uint8_t> coinb_bin(coinbase.length() / 2);
    hexToBytes(coinbase, coinb_bin.data(), coinb_bin.size());

    uint8_t merkle_root[32];
    doubleSHA256(coinb_bin.data(), coinb_bin.size(), merkle_root);

    for (const auto& branch : job.merkle_branch) {
        std::vector<uint8_t> branch_bin(branch.length() / 2);
        hexToBytes(branch, branch_bin.data(), branch_bin.size());
        uint8_t concat[64];
        memcpy(concat, merkle_root, 32);
        memcpy(concat + 32, branch_bin.data(), 32);
        doubleSHA256(concat, 64, merkle_root);
    }

    return bin2hex(merkle_root, 32);
}

// ==================== MINING THREAD ====================
void minerThread(int threadId) {
    uint8_t header[80];
    uint8_t target[32];
    uint8_t hash[32];
    std::string extranonce2_hex;
    uint32_t nonce;
    std::string localExtranonce2;

    while (true) {
        if (shouldStopMining) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (!jobReceived || solutionFound) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        StratumJob localJob;
        {
            std::lock_guard<std::mutex> lock(jobMutex);
            localJob = currentJob;
            uint32_t counter = extranonce2_counter++;
            std::stringstream ss;
            ss << std::hex << std::setfill('0') << std::setw(extranonce2_size * 2) << counter;
            localExtranonce2 = ss.str();
            if (localExtranonce2.length() > extranonce2_size * 2)
                localExtranonce2 = localExtranonce2.substr(localExtranonce2.length() - extranonce2_size * 2);
        }

        std::string merkleRootHex = buildMerkleRoot(localJob, localExtranonce2);

        memset(header, 0, 80);
        hexToBytes(localJob.version, header, 4);
        reverseBytes(header, 4);
        hexToBytes(localJob.prevhash, header + 4, 32);
        reverseBytes(header + 4, 32);
        hexToBytes(merkleRootHex, header + 36, 32);
        reverseBytes(header + 36, 32);
        hexToBytes(localJob.ntime, header + 68, 4);
        reverseBytes(header + 68, 4);
        hexToBytes(localJob.nbits, header + 72, 4);
        reverseBytes(header + 72, 4);

        // Tính target
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

        // Chia nonce range
        uint32_t startNonce, endNonce;
        uint64_t totalNonces = 1ULL << 32;
        uint64_t noncesPerThread = totalNonces / numThreads;
        startNonce = static_cast<uint32_t>(threadId * noncesPerThread);
        endNonce = (static_cast<unsigned int>(threadId) == numThreads - 1)
                       ? UINT32_MAX
                       : static_cast<uint32_t>((threadId + 1) * noncesPerThread) - 1;

        for (nonce = startNonce; nonce <= endNonce && !solutionFound && !shouldStopMining; ++nonce) {
            memcpy(header + 76, &nonce, 4);
            sha.hashBlockHeader(header, hash);   // double SHA256 luôn
            totalHashes.fetch_add(1, std::memory_order_relaxed);

            // check target
            bool valid = true;
            for (int i = 31; i >= 0; i--) {
                if (hash[i] < target[i]) break;
                if (hash[i] > target[i]) { valid = false; break; }
            }
            if (valid) {
                std::lock_guard<std::mutex> lock(submitMutex);
                if (!solutionFound) {
                    solutionFound = true;
                    bestNonce = nonce;
                    memcpy(bestHash, hash, 32);
                    std::cout << "🏆 BLOCK FOUND by thread " << threadId
                              << "! Nonce: 0x" << std::hex << nonce << std::dec
                              << ", extranonce2: " << localExtranonce2 << std::endl;
                    // Submit sẽ được main thread gọi
                }
                break;
            }
        }

        if (!solutionFound && !shouldStopMining)
            jobReceived = false;
    }
}

// ==================== BÁO CÁO HASHRATE ====================
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
                  << currentTotal << " hashes | Pool: " << poolHost << std::endl;

        lastTotalHashes = currentTotal;
        lastReport = steady_clock::now();
    }
}

// ==================== MAIN ====================
std::atomic<bool> exitFlag{false};
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
    std::cout << "🚀 Starting BTC Stratum Miner\n";
    std::cout << "   Pool: " << poolHost << ":" << poolPort << "\n";
    std::cout << "   Address: " << btcAddress << "\n";
    std::cout << "   Worker: " << walletName << "\n";
    std::cout << "   Threads: " << numThreads << "\n\n";

    stratumConnect();

    for (unsigned int i = 0; i < numThreads; ++i) {
        threads.emplace_back(minerThread, i);
    }

    std::thread(reportStats).detach();

    while (!exitFlag) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (solutionFound) {
            // Lấy extranonce2 từ biến lưu (cần thêm cơ chế lưu)
            // Ở đây ta tạm dùng extranonce2_counter-1 vì solutionFound set khi extranonce2_counter đã tăng
            // Đơn giản ta dùng một biến toàn cục lưu lúc tìm thấy.
            std::cout << "⚠️ Submit not fully implemented (need extranonce2), exiting" << std::endl;
            exit(0);
        }

        if (!stratumClient && !btcAddress.empty()) {
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
