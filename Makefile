# ──────────────────────────────────────────────────
#  Makefile – Stratum CPU Miner (a-Shell Full)
# ──────────────────────────────────────────────────

CXX = clang++

# Phát hiện kiến trúc thực sự
UNAME_M != uname -m
UNAME_S != uname -s

# Mọi thiết bị Apple iOS/macOS đều là ARM64 (trừ Mac Intel cũ)
.if $(UNAME_S) == "Darwin" || $(UNAME_M:MiPhone*) != "" || $(UNAME_M:MiPad*) != ""
    # iOS / macOS – luôn là ARM64 (a-Shell)
    MARCH_FLAG = -mcpu=apple-a13
    TARGET_FLAG = -target arm64-apple-ios
    PLATFORM_DEFINES = -D__ARM_NEON__ -D__aarch64__
.elif $(UNAME_M) == "aarch64" || $(UNAME_M) == "arm64"
    # Linux ARM64
    MARCH_FLAG = -mcpu=cortex-a72
    TARGET_FLAG =
    PLATFORM_DEFINES = -D__ARM_NEON__ -D__aarch64__
.else
    # x86-64 fallback
    MARCH_FLAG = -march=native
    TARGET_FLAG =
    PLATFORM_DEFINES =
.endif

CXXFLAGS = -std=c++17 -O3 $(MARCH_FLAG) $(TARGET_FLAG) -Wall -Wextra $(PLATFORM_DEFINES) -DASIO_STANDALONE
INCLUDES = -I.
LDFLAGS = -lpthread

TARGET = miner
SRCS = miner.cpp
OBJS = miner.o

all: detect $(TARGET)

detect:
	@echo "========================================="
	@echo "  Device:       $(UNAME_M)"
	@echo "  System:       $(UNAME_S)"
	@echo "  March:        $(MARCH_FLAG)"
	@echo "  Target:       $(TARGET_FLAG)"
	@echo "  Defines:      $(PLATFORM_DEFINES)"
	@echo "========================================="

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(SRCS) -o $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all detect clean
