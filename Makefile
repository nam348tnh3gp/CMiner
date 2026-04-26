# Trình biên dịch và các cờ
CXX      = g++
CXXFLAGS = -std=c++11 -O3 -march=native -mtune=native -Wall -Wextra -pthread
LDFLAGS  = -pthread

# Tên file thực thi và các file nguồn
TARGET   = miner
SRCS     = miner.cpp
OBJS     = $(SRCS:.cpp=.o)
HEADERS  = DSHA2.h

# Mục tiêu mặc định
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Quy tắc tường minh để biên dịch .cpp -> .o, phụ thuộc vào header
%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Dọn dẹp
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
