#include "DSHA2.h"
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
#include <csignal>

// ========== Thư viện WebSocket & JSON ==========
#include <ixwebsocket/IXWebSocket.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std::chrono;

// ==================== CẤU TRÚC BLOCK HEADER ====================
struct BlockHeader {
    uint32_t version;
    unsigned char prevBlockHash[32];
    unsigned char merkleRoot[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};

// ==================== TOÀN CỤC ====================
DSHA256 sha;

// Pool & user
std::string poolHost = "public-pool.io";
int poolPort = 3333;
std::string btcAddress;
std::string walletName = "CPUMiner";

// Backup pools
struct PoolInfo {
    std::string host;
    int port;
    bool ssl;
};
std::vector<PoolInfo> backupPools = {
    {"public-pool.io", 3333, false},
    {"public-pool.io", 4333, true},
    {"pool.vkbit.com", 3333, false},
    {"stratum.slushpool.com", 3333, false}
};
int currentPoolIndex = 0;

// Stratum state
ix::WebSocket ws;
bool wsConnected = false;
std::string jobId;
uint8_t header[80];
uint8_t target[32];
std::mutex jobMutex;

// Mining state
std::atomic<bool> solutionFound{false};
std::atomic<bool> shouldStopMining{false};
std::atomic<uint64_t> totalHashes{0};
uint32_t bestNonce = 0;
unsigned char bestHash[32];
std::mutex submitMutex;

// Thread control
unsigned int numThreads;
std::vector<std::thread> threads;
std::atomic<bool> jobReceived{false};
auto startTime = steady_clock::now();
auto lastReport = steady_clock::now();
uint64_t lastTotalHashes = 0;

// Forward declarations
void stratumConnect();
void parseMessage(const std::string& msg);

// ==================== HEX/BYTE HELPERS ====================
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

// ==================== STRATUM ====================
void stratumSend(const std::string& jsonStr) {
    if (wsConnected) {
        ws.send(jsonStr);
    }
}

void stratumSubscribe() {
    json doc;
    doc["id"] = 1;
    doc["method"] = "mining.subscribe";
    doc["params"] = json::array({walletName + "/1.0"});
    std::string s = doc.dump();
    std::cout << "📡 Subscribing: " << s << std::endl;
    stratumSend(s);
}

void stratumAuthorize() {
    json doc;
    doc["id"] = 2;
    doc["method"] = "mining.authorize";
    std::string user = btcAddress + "." + walletName;
    doc["params"] = json::array({user, "x"});
    std::string s = doc.dump();
    std::cout << "🔑 Authorizing: " << user << std::endl;
    stratumSend(s);
}

void stratumSubmit(uint32_t nonce) {
    json doc;
    doc["id"] = 4;
    doc["method"] = "mining.submit";
    std::string user = btcAddress + "." + walletName;
    std::stringstream ss;
    ss << std::hex << nonce;
    doc["params"] = json::array({user, jobId, "", "", ss.str()});
    std::string s = doc.dump();
    std::cout << "🎯 Submitting nonce: 0x" << ss.str() << std::endl;
    stratumSend(s);
}

// ==================== WebSocket Event ====================
void onMessage(const ix::WebSocketMessagePtr& msg) {
    switch (msg->type) {
        case ix::WebSocketMessageType::Open:
            std::cout << "✅ Connected to pool " << poolHost << ":" << poolPort << std::endl;
            wsConnected = true;
            stratumSubscribe();
            break;
        case ix::WebSocketMessageType::Close:
            std::cout << "❌ Disconnected from " << poolHost << std::endl;
            wsConnected = false;
            jobReceived = false;
            shouldStopMining = true;
            // Chuyển pool dự phòng
            currentPoolIndex = (currentPoolIndex + 1) % backupPools.size();
            poolHost = backupPools[currentPoolIndex].host;
            poolPort = backupPools[currentPoolIndex].port;
            std::cout << "🔄 Switching to pool: " << poolHost << ":" << poolPort << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            stratumConnect();
            break;
        case ix::WebSocketMessageType::Message:
            parseMessage(msg->str);
            break;
        case ix::WebSocketMessageType::Error:
            std::cerr << "⚠️ WebSocket error: " << msg->errorInfo.reason << std::endl;
            break;
        default:
            break;
    }
}

void parseMessage(const std::string& msgStr) {
    try {
        json doc = json::parse(msgStr);
        
        // mining.notify
        if (doc.contains("method") && doc["method"] == "mining.notify") {
            auto params = doc["params"];
            if (params.size() < 8) return;
            
            jobId = params[0].get<std::string>();
            std::string prevHashHex = params[1];
            std::string merkleHex = params[3];
            std::string versionHex = params[5];
            std::string nbitsHex = params[6];
            std::string ntimeHex = params[7];
            
            // Build header (80 bytes)
            memset(header, 0, 80);
            // version (little-endian)
            hexToBytes(versionHex, header, 4);
            reverseBytes(header, 4);
            // prevhash
            hexToBytes(prevHashHex, header + 4, 32);
            reverseBytes(header + 4, 32);
            // merkle root
            hexToBytes(merkleHex, header + 36, 32);
            reverseBytes(header + 36, 32);
            // timestamp
            hexToBytes(ntimeHex, header + 68, 4);
            reverseBytes(header + 68, 4);
            // bits
            hexToBytes(nbitsHex, header + 72, 4);
            reverseBytes(header + 72, 4);
            // nonce sẽ được điền sau
            
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
            
            // Reset mining
            solutionFound = false;
            shouldStopMining = false;
            totalHashes = 0;
            lastTotalHashes = 0;
            jobReceived = true;
            startTime = steady_clock::now();
            lastReport = startTime;
            std::cout << "📦 New job #" << jobId << " from " << poolHost << std::endl;
        }
        
        // Response to subscribe (id=1) -> authorize
        if (doc.contains("id") && doc["id"] == 1 && doc.contains("result")) {
            stratumAuthorize();
        }
        
        // Response to authorize (id=2)
        if (doc.contains("id") && doc["id"] == 2) {
            bool success = doc["result"].get<bool>();
            if (!success) {
                std::cerr << "❌ Auth failed on " << poolHost << std::endl;
                // Switch pool
                ws.stop();
            } else {
                std::cout << "🔑 Authorized on " << poolHost << std::endl;
            }
        }
        
        // Submit response (id=4)
        if (doc.contains("id") && doc["id"] == 4) {
            bool accepted = doc["result"].get<bool>();
            std::cout << (accepted ? "✅ Share accepted!" : "❌ Share rejected!") << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    }
}

void stratumConnect() {
    if (btcAddress.empty()) {
        std::cerr << "⚠️ BTC address not set. Use -a <address>" << std::endl;
        return;
    }
    
    bool useSSL = (poolPort == 4333 || poolPort == 443);
    std::string url = (useSSL ? "wss://" : "ws://") + poolHost + ":" + std::to_string(poolPort) + "/";
    std::cout << "🔌 Connecting to " << url << std::endl;
    
    ws.setUrl(url);
    ws.setOnMessageCallback(onMessage);
    ws.start();
}

// ==================== MINING THREAD ====================
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
        
        // Sao chép header gốc
        {
            std::lock_guard<std::mutex> lock(jobMutex);
            memcpy(&localHeader, header, 80);
        }
        
        // Chia nonce range
        uint32_t startNonce, endNonce;
        uint64_t totalNonces = 1ULL << 32;
        uint64_t noncesPerThread = totalNonces / numThreads;
        startNonce = static_cast<uint32_t>(threadId * noncesPerThread);
        if (threadId == numThreads - 1) {
            endNonce = UINT32_MAX;
        } else {
            endNonce = static_cast<uint32_t>((threadId + 1) * noncesPerThread) - 1;
        }
        
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
        
        // Nếu đã duyệt hết range và không tìm thấy, chờ job mới
        if (!solutionFound && !shouldStopMining) {
            jobReceived = false; // yêu cầu job mới
        }
    }
}

// ==================== IN THỐNG KÊ ====================
void reportStats() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (shouldStopMining) continue;
        
        uint64_t currentTotal = totalHashes.load(std::memory_order_relaxed);
        uint64_t delta = currentTotal - lastTotalHashes;
        double elapsed = duration_cast<duration<double>>(steady_clock::now() - lastReport).count();
        double hashrate = delta / elapsed; // H/s
        
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "⚡ Hashrate: " << (hashrate / 1e6) << " MH/s | Total: " 
                  << currentTotal << " hashes | Pool: " << poolHost << std::endl;
        
        lastTotalHashes = currentTotal;
        lastReport = steady_clock::now();
    }
}

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    // Parse command line
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" || arg == "--pool") {
            if (i + 1 < argc) {
                poolHost = argv[++i];
                // Tìm port mặc định
                bool found = false;
                for (auto& bp : backupPools) {
                    if (bp.host == poolHost) {
                        poolPort = bp.port;
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
        std::cerr << "Usage: " << argv[0] << " -a <btc_address> [-o pool_host] [-p port] [-w worker] [-t threads]" << std::endl;
        return 1;
    }
    
    numThreads = (numThreads > 0) ? numThreads : std::thread::hardware_concurrency();
    std::cout << "🚀 Starting miner on " << poolHost << ":" << poolPort << std::endl;
    std::cout << "   Address: " << btcAddress << std::endl;
    std::cout << "   Worker: " << walletName << std::endl;
    std::cout << "   Threads: " << numThreads << std::endl;
    
    // Khởi tạo WebSocket
    ix::initNetSystem();
    
    // Bắt đầu kết nối
    stratumConnect();
    
    // Khởi động các luồng đào
    for (unsigned int i = 0; i < numThreads; ++i) {
        threads.emplace_back(minerThread, i);
    }
    
    // Luồng báo cáo
    std::thread reporter(reportStats);
    reporter.detach();
    
    // Vòng lặp chính xử lý solution
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (solutionFound) {
            stratumSubmit(bestNonce);
            solutionFound = false;
            jobReceived = false;
            shouldStopMining = true; // tạm dừng đến khi có job mới
        }
        
        // Reconnect nếu cần
        if (!wsConnected && !btcAddress.empty()) {
            static auto lastReconnect = steady_clock::now();
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - lastReconnect).count() > 10) {
                lastReconnect = now;
                std::cout << "🔄 Reconnecting..." << std::endl;
                stratumConnect();
            }
        }
    }
    
    ws.stop();
    ix::uninitNetSystem();
    return 0;
}
