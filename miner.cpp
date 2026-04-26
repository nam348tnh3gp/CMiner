/**
 * BTC Lottery Miner - CLI Edition
 * Hỗ trợ: Multi-thread, Stratum qua WebSocket (WS/WSS), tự động chuyển pool,
 *         Double SHA256 bằng phần mềm (DSHA2.h), hiển thị hashrate.
 * Dịch: g++ -std=c++17 -O3 ...
 */

#include "DSHA2.h"
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
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
#include <variant>
#include <csignal>

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;
namespace ssl = net::ssl;
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

// ==================== HÀM BĂM SHA256 KÉP ====================
DSHA256 sha;

// ==================== THAM SỐ NGƯỜI DÙNG ====================
std::string poolHost = "public-pool.io";
int poolPort = 3333;
std::string btcAddress;
std::string walletName = "CPUMiner";

// Danh sách pool dự phòng
struct PoolInfo {
    std::string host;
    int port;
    bool ssl;               // true nếu dùng WSS
};
std::vector<PoolInfo> backupPools = {
    {"public-pool.io", 3333, false},
    {"public-pool.io", 4333, true},
    {"pool.vkbit.com", 3333, false},
    {"stratum.slushpool.com", 3333, false}
};
int currentPoolIndex = 0;   // pool đang dùng

// ==================== TRẠNG THÁI STRATUM ====================
std::string jobId;
uint8_t header[80];         // block header đang đào
uint8_t target[32];         // target để so sánh
std::mutex jobMutex;

// Cờ điều khiển đào
std::atomic<bool> solutionFound{false};
std::atomic<bool> shouldStopMining{false};
std::atomic<uint64_t> totalHashes{0};
uint32_t bestNonce = 0;
unsigned char bestHash[32];
std::mutex submitMutex;

// Số luồng CPU
unsigned int numThreads;
std::vector<std::thread> threads;
std::atomic<bool> jobReceived{false};

// Thời gian & báo cáo
steady_clock::time_point startTime;
steady_clock::time_point lastReport;
uint64_t lastTotalHashes = 0;

// ==================== WEBSOCKET CLIENT ĐA NỀN (WS / WSS) ====================
using ws_stream = websocket::stream<tcp::socket>;
using wss_stream = websocket::stream<ssl::stream<tcp::socket>>;

class StratumClient {
public:
    using OnMessage = std::function<void(const std::string&)>;
    using OnDisconnect = std::function<void()>;

    StratumClient() : ioc_(1), resolver_(ioc_), ssl_ctx_(ssl::context::tlsv12_client) {
        // Không xác thực certificate (chỉ dùng cho pool công cộng)
        ssl_ctx_.set_verify_mode(ssl::verify_none);
    }

    void connect(const std::string& host, const std::string& port, bool useSSL) {
        host_ = host;
        port_ = port;
        useSSL_ = useSSL;
        if (useSSL) {
            ws_.emplace<wss_stream>(ioc_, ssl_ctx_);
        } else {
            ws_.emplace<ws_stream>(ioc_);
        }
        thread_ = std::thread([this]() { run(); });
    }

    void send(const std::string& msg) {
        net::post(ioc_, [this, msg]() {
            std::visit([&](auto& ws) {
                using T = std::decay_t<decltype(ws)>;
                if constexpr (!std::is_same_v<T, std::monostate>) {
                    try {
                        ws.write(net::buffer(msg));
                    } catch (...) {}
                }
            }, ws_);
        });
    }

    void setOnMessage(OnMessage cb) { onMessage_ = std::move(cb); }
    void setOnDisconnect(OnDisconnect cb) { onDisconnect_ = std::move(cb); }

    void stop() {
        net::post(ioc_, [this]() {
            std::visit([&](auto& ws) {
                using T = std::decay_t<decltype(ws)>;
                if constexpr (!std::is_same_v<T, std::monostate>) {
                    try {
                        if (ws.is_open())
                            ws.close(websocket::close_code::normal);
                    } catch (...) {}
                }
            }, ws_);
            ioc_.stop();
        });
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        try {
            auto const results = resolver_.resolve(host_, port_);
            if (useSSL_) {
                auto& wss = std::get<wss_stream>(ws_);
                auto ep = net::connect(get_lowest_layer(wss), results);
                // SNI hostname
                if (!SSL_set_tlsext_host_name(wss.next_layer().native_handle(), host_.c_str()))
                    throw beast::system_error(beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()));
                wss.next_layer().handshake(ssl::stream_base::client);
                wss.handshake(host_ + ":" + std::to_string(ep.port()), "/");
                std::cout << "✅ Connected (WSS) to " << host_ << ":" << ep.port() << std::endl;
                readLoop(wss);
            } else {
                auto& ws = std::get<ws_stream>(ws_);
                auto ep = net::connect(ws.next_layer(), results);
                ws.handshake(host_ + ":" + std::to_string(ep.port()), "/");
                std::cout << "✅ Connected (WS) to " << host_ << ":" << ep.port() << std::endl;
                readLoop(ws);
            }
        } catch (const std::exception& e) {
            std::cerr << "❌ WebSocket error: " << e.what() << std::endl;
        }
        // Sau khi vòng lặp kết thúc (lỗi hoặc bị đóng)
        if (onDisconnect_) onDisconnect_();
    }

    // Vòng lặp đọc tin nhắn (dùng template để dùng chung cho cả ws và wss)
    template<typename Stream>
    void readLoop(Stream& stream) {
        beast::flat_buffer buffer;
        while (true) {
            stream.read(buffer);
            std::string msg = beast::buffers_to_string(buffer.data());
            buffer.clear();
            if (onMessage_) onMessage_(msg);
        }
    }

    net::io_context ioc_;
    tcp::resolver resolver_;
    ssl::context ssl_ctx_;
    std::variant<std::monostate, ws_stream, wss_stream> ws_;
    std::string host_, port_;
    bool useSSL_;
    std::thread thread_;
    OnMessage onMessage_;
    OnDisconnect onDisconnect_;
};

std::unique_ptr<StratumClient> wsClient;

// ==================== TIỆN ÍCH HEX / BYTE ====================
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

// ==================== GIAO THỨC STRATUM ====================
void stratumSend(const std::string& jsonStr) {
    if (wsClient) wsClient->send(jsonStr);
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
    std::stringstream ss;
    ss << std::hex << nonce;
    json req;
    req["id"] = 4;
    req["method"] = "mining.submit";
    req["params"] = json::array({btcAddress + "." + walletName, jobId, "", "", ss.str()});
    std::cout << "🎯 Submitting nonce: 0x" << ss.str() << std::endl;
    stratumSend(req.dump());
}

// ==================== XỬ LÝ TIN NHẮN TỪ POOL ====================
void onWsMessage(const std::string& msg) {
    try {
        json doc = json::parse(msg);

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

            // Xây dựng header 80 byte
            memset(header, 0, 80);
            // version
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

            // Tính target từ bits
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

            // Reset trạng thái đào
            solutionFound = false;
            shouldStopMining = false;
            totalHashes = 0;
            lastTotalHashes = 0;
            jobReceived = true;
            startTime = steady_clock::now();
            lastReport = startTime;
            std::cout << "📦 New job #" << jobId << " from " << poolHost << std::endl;
        }

        // Phản hồi subscribe -> authorize
        if (doc.contains("id") && doc["id"] == 1 && doc.contains("result")) {
            stratumAuthorize();
        }

        // Phản hồi authorize
        if (doc.contains("id") && doc["id"] == 2) {
            bool success = doc["result"].get<bool>();
            if (!success) {
                std::cerr << "❌ Auth failed" << std::endl;
                if (wsClient) wsClient->stop();
            } else {
                std::cout << "🔑 Authorized successfully" << std::endl;
            }
        }

        // Phản hồi submit
        if (doc.contains("id") && doc["id"] == 4) {
            bool accepted = doc["result"].get<bool>();
            std::cout << (accepted ? "✅ Share accepted!" : "❌ Share rejected!") << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    }
}

void onWsDisconnect() {
    std::cout << "❌ Pool disconnected" << std::endl;
    // Chuyển sang pool dự phòng tiếp theo
    currentPoolIndex = (currentPoolIndex + 1) % backupPools.size();
    poolHost = backupPools[currentPoolIndex].host;
    poolPort = backupPools[currentPoolIndex].port;
    std::cout << "🔄 Switching to pool: " << poolHost << ":" << poolPort
              << (backupPools[currentPoolIndex].ssl ? " (WSS)" : " (WS)") << std::endl;
    jobReceived = false;
    shouldStopMining = true;
}

// ==================== KẾT NỐI ĐẾN POOL ====================
void stratumConnect() {
    if (btcAddress.empty()) {
        std::cerr << "⚠️ BTC address not set!" << std::endl;
        return;
    }
    // Hủy client cũ nếu có
    if (wsClient) {
        wsClient->stop();
        wsClient.reset();
    }

    // Xác định có dùng SSL không
    bool useSSL = (poolPort == 4333 || poolPort == 443 ||
                   backupPools[currentPoolIndex].ssl);

    wsClient = std::make_unique<StratumClient>();
    wsClient->setOnMessage(onWsMessage);
    wsClient->setOnDisconnect([]() {
        // Gọi từ thread của StratumClient
        onWsDisconnect();
    });
    wsClient->connect(poolHost, std::to_string(poolPort), useSSL);
}

// ==================== LUỒNG ĐÀO ====================
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

        // Sao chép header gốc (an toàn luồng)
        {
            std::lock_guard<std::mutex> lock(jobMutex);
            memcpy(&localHeader, header, 80);
        }

        // Chia nonce range
        uint32_t startNonce, endNonce;
        uint64_t totalNonces = 1ULL << 32;
        uint64_t noncesPerThread = totalNonces / numThreads;
        startNonce = static_cast<uint32_t>(threadId * noncesPerThread);
        endNonce = (threadId == numThreads - 1)
                       ? UINT32_MAX
                       : static_cast<uint32_t>((threadId + 1) * noncesPerThread) - 1;

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

        // Nếu đã quét hết range mà không tìm thấy, yêu cầu job mới
        if (!solutionFound && !shouldStopMining) {
            jobReceived = false;
        }
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
        double hashrate = delta / elapsed;  // H/s

        std::cout << std::fixed << std::setprecision(2);
        std::cout << "⚡ " << hashrate / 1e6 << " MH/s | Total: "
                  << currentTotal << " hashes | Pool: " << poolHost << std::endl;

        lastTotalHashes = currentTotal;
        lastReport = steady_clock::now();
    }
}

// ==================== XỬ LÝ TÍN HIỆU THOÁT ====================
std::atomic<bool> exitFlag{false};
void signalHandler(int) {
    exitFlag = true;
    shouldStopMining = true;
    if (wsClient) wsClient->stop();
}

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    // Đăng ký tín hiệu thoát
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Parse tham số dòng lệnh
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" || arg == "--pool") {
            if (i + 1 < argc) {
                poolHost = argv[++i];
                // Tìm port mặc định từ danh sách dự phòng
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
        std::cerr << "Usage: " << argv[0]
                  << " -a <btc_address> [-o pool_host] [-p port] [-w worker] [-t threads]\n";
        return 1;
    }

    numThreads = (numThreads > 0) ? numThreads : std::thread::hardware_concurrency();
    std::cout << "🚀 Starting BTC Lottery Miner CLI" << std::endl;
    std::cout << "   Pool: " << poolHost << ":" << poolPort
              << (backupPools[currentPoolIndex].ssl ? " (WSS)" : " (WS)") << std::endl;
    std::cout << "   Address: " << btcAddress << std::endl;
    std::cout << "   Worker: " << walletName << std::endl;
    std::cout << "   Threads: " << numThreads << "\n" << std::endl;

    // Kết nối pool đầu tiên
    stratumConnect();

    // Khởi động các luồng đào
    for (unsigned int i = 0; i < numThreads; ++i) {
        threads.emplace_back(minerThread, i);
    }

    // Luồng báo cáo (detach, sẽ tự kết thúc khi chương trình dừng)
    std::thread(reportStats).detach();

    // Vòng lặp chính
    while (!exitFlag) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Nếu tìm thấy solution
        if (solutionFound) {
            stratumSubmit(bestNonce);
            solutionFound = false;
            jobReceived = false;
            shouldStopMining = true; // tạm dừng, sẽ có job mới
        }

        // Tự động reconnect nếu client đã bị hủy (do lỗi hoặc chuyển pool)
        if (!wsClient && !btcAddress.empty()) {
            static auto lastReconnect = steady_clock::now();
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - lastReconnect).count() > 10) {
                lastReconnect = now;
                std::cout << "🔄 Reconnecting..." << std::endl;
                stratumConnect();
            }
        }

        // Nếu wsClient tồn tại nhưng bên trong đã đóng và chưa reset, cần kiểm tra thêm?
        // Ở đây ta dựa vào callback onWsDisconnect đã đặt pool mới và sẽ được main thread reconnect.
    }

    // Dừng tất cả luồng
    shouldStopMining = true;
    if (wsClient) wsClient->stop();
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    std::cout << "👋 Miner stopped." << std::endl;
    return 0;
}
