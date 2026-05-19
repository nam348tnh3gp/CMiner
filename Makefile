# ─────────────────────────────────────────────────────
#  Makefile – Stratum CPU Miner (a‑Shell / Multi‑Arch)
# ─────────────────────────────────────────────────────

# Trình biên dịch (có thể đổi thành clang++-18 nếu cần)
CXX ?= clang++

# ─── Phát hiện HĐH & kiến trúc ───
UNAME_S != uname -s
UNAME_M != uname -m

# Kiểm tra xem có phải Apple iOS/macOS không (Darwin + model iPhone/iPad)
.if $(UNAME_S) == "Darwin" && ( $(UNAME_M:MiPhone*) != "" || $(UNAME_M:MiPad*) != "" )
    PLATFORM = ios-arm64
.elif $(UNAME_S) == "Darwin" && ( $(UNAME_M) == "arm64" || $(UNAME_M) == "arm64e" )
    PLATFORM = macos-arm64
.elif $(UNAME_S) == "Linux" && ( $(UNAME_M) == "aarch64" || $(UNAME_M) == "arm64" )
    PLATFORM = linux-arm64
.elif $(UNAME_S) == "Linux" && ( $(UNAME_M) == "x86_64" || $(UNAME_M) == "amd64" )
    PLATFORM = linux-x86_64
.else
    PLATFORM = unknown
.endif

# ─── Cấu hình theo nền tảng ───
.if $(PLATFORM) == "ios-arm64"
    MCPU_FLAG = -mcpu=apple-a13
    TARGET_FLAG = -target arm64-apple-ios
    # Tự động tìm SDK sysroot (nếu có)
    SYSROOT != xcrun --sdk iphoneos --show-sdk-path 2>/dev/null
    .if $(SYSROOT) != ""
        SYSROOT_FLAG = -isysroot $(SYSROOT)
    .else
        SYSROOT_FLAG =
    .endif
    PLATFORM_DEFINES = -D__ARM_NEON__ -D__aarch64__ -D__APPLE__
    LDFLAGS = -lpthread
    # Trên iOS, Boost.Asio chỉ dùng header, không cần -lboost_system
    ASIO_FLAG = -DASIO_STANDALONE
.elif $(PLATFORM) == "macos-arm64"
    MCPU_FLAG = -mcpu=apple-a13
    TARGET_FLAG =
    SYSROOT_FLAG =
    PLATFORM_DEFINES = -D__ARM_NEON__ -D__aarch64__ -D__APPLE__
    LDFLAGS = -lpthread -lcrypto -lssl
    ASIO_FLAG = -DASIO_STANDALONE
.elif $(PLATFORM) == "linux-arm64"
    MCPU_FLAG = -mcpu=cortex-a72
    TARGET_FLAG =
    SYSROOT_FLAG =
    PLATFORM_DEFINES = -D__ARM_NEON__ -D__aarch64__
    LDFLAGS = -lpthread -lcrypto -lssl
    ASIO_FLAG = -DASIO_STANDALONE
.elif $(PLATFORM) == "linux-x86_64"
    MCPU_FLAG = -march=native
    TARGET_FLAG =
    SYSROOT_FLAG =
    PLATFORM_DEFINES = -D__SSE4_2__ -D__AVX2__
    LDFLAGS = -lpthread -lcrypto -lssl
    ASIO_FLAG = -DASIO_STANDALONE
.else
    $(warning Unknown platform, using generic flags)
    MCPU_FLAG =
    TARGET_FLAG =
    SYSROOT_FLAG =
    PLATFORM_DEFINES =
    LDFLAGS = -lpthread -lcrypto -lssl
    ASIO_FLAG = -DASIO_STANDALONE
.endif

# ─── Cờ biên dịch chung ───
CXXFLAGS = -std=c++17 -O3 $(MCPU_FLAG) $(TARGET_FLAG) $(SYSROOT_FLAG) \
           -Wall -Wextra $(PLATFORM_DEFINES) $(ASIO_FLAG)

INCLUDES = -I.

# ─── Tên file ───
TARGET = miner
SRCS = miner.cpp
OBJS = miner.o

# ─── Targets ───
all: detect $(TARGET)
	@echo "[OK] Build successful → $(TARGET)"

detect:
	@echo "========================================="
	@echo "  Platform:     $(PLATFORM)"
	@echo "  Device:       $(UNAME_M)"
	@echo "  CPU flags:    $(MCPU_FLAG)"
	@echo "  Target:       $(TARGET_FLAG)"
	@echo "  Sysroot:      $(SYSROOT_FLAG)"
	@echo "  Defines:      $(PLATFORM_DEFINES)"
	@echo "========================================="

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(SRCS) -o $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all detect clean
