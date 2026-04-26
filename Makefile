CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -Wall -Wextra
LDFLAGS = -lixwebsocket -lpthread

# Thư mục chứa DSHA2.h nếu để cùng thư mục
INCLUDES = -I.

TARGET = miner

SRCS = miner.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
