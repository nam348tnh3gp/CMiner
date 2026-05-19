# ──────────────────────────────────────────────────
#  Makefile – Stratum CPU Miner (Auto-detect CPU)
# ──────────────────────────────────────────────────

# Trình biên dịch
CXX = g++

# Phát hiện kiến trúc CPU
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
    # Apple Silicon / a-Shell (ARM64)
    MARCH_FLAG = -mcpu=apple-a13
    PLATFORM_DEFINES = -D__ARM_NEON__
else ifeq ($(UNAME_M),aarch64)
    # Linux ARM64 (Raspberry Pi 4/5, server ARM...)
    MARCH_FLAG = -mcpu=cortex-a72
    PLATFORM_DEFINES = -D__ARM_NEON__
else ifneq ($(filter x86_64 amd64,$(UNAME_M)),)
    # x86-64 (Intel/AMD)
    MARCH_FLAG = -march=native
    PLATFORM_DEFINES = -D__SSE4_2__ -D__AVX2__
else
    # Fallback: để compiler tự quyết định
    MARCH_FLAG =
    PLATFORM_DEFINES =
endif

# Cờ biên dịch
CXXFLAGS = -std=c++17 -O3 $(MARCH_FLAG) -Wall -Wextra $(PLATFORM_DEFINES)

# Đường dẫn include
INCLUDES = -I.

# Thư viện liên kết
# Boost.Asio (header-only nếu dùng standalone, nếu không thì cần -lboost_system)
# OpenSSL (nếu dùng SHA-256 từ OpenSSL thay vì DSHA2.h) → bỏ nếu không cần
# pthread (luôn cần cho std::thread)
LDFLAGS = -lboost_system -lpthread

# ─── Tên file ───
TARGET = miner
SRCS = miner.cpp
OBJS = $(SRCS:.cpp=.o)

# ─── Build rules ───
all: detect $(TARGET)
	@echo "[OK] Build complete: $(TARGET)"
	@echo "[INFO] Architecture: $(UNAME_M)"
	@echo "[INFO] March flag: $(MARCH_FLAG)"

# In thông tin phát hiện CPU
detect:
	@echo "========================================="
	@echo "  CPU Detected: $(UNAME_M)"
	@echo "  March flag:   $(MARCH_FLAG)"
	@echo "  Platform:     $(PLATFORM_DEFINES)"
	@echo "========================================="

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# ─── Clean ───
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "[CLEAN] Done."

# ─── Helper targets ───
.PHONY: all clean detect

# Kiểm tra compiler info
compiler-info:
	@echo "Compiler: $(CXX)"
	@$(CXX) --version | head -1
	@echo "Flags: $(CXXFLAGS)"

# Build và chạy test hash (nếu có file test riêng)
test: all
	./$(TARGET) --self-test
