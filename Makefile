# ──────────────────────────────────────────────────
#  Makefile – Stratum CPU Miner (BSD Make / a-Shell)
# ──────────────────────────────────────────────────

# Trình biên dịch
CXX = clang++

# Phát hiện kiến trúc CPU
UNAME_M != uname -m

.if $(UNAME_M) == "arm64"
    # Apple Silicon / a-Shell (ARM64)
    MARCH_FLAG = -mcpu=apple-a13 -target arm64-apple-ios
    PLATFORM_DEFINES = -D__ARM_NEON__
.elif $(UNAME_M) == "aarch64"
    # Linux ARM64
    MARCH_FLAG = -mcpu=cortex-a72
    PLATFORM_DEFINES = -D__ARM_NEON__
.else
    # x86-64 / Fallback
    MARCH_FLAG = -march=native
    PLATFORM_DEFINES =
.endif

# Cờ biên dịch
CXXFLAGS = -std=c++17 -O3 $(MARCH_FLAG) -Wall -Wextra $(PLATFORM_DEFINES) -DASIO_STANDALONE

# Đường dẫn include
INCLUDES = -I.

# Thư viện (bỏ boost nếu dùng ASIO_STANDALONE)
LDFLAGS = -lpthread

# ─── Tên file ───
TARGET = miner
SRCS = miner.cpp
OBJS = miner.o

# ─── Build rules ───
all: detect $(TARGET)

detect:
	@echo "========================================="
	@echo "  CPU Detected: $(UNAME_M)"
	@echo "  March flag:   $(MARCH_FLAG)"
	@echo "  Platform:     $(PLATFORM_DEFINES)"
	@echo "========================================="

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(SRCS) -o $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all detect clean
