#ifndef DSHA2_H
#define DSHA2_H

#include <cstdint>
#include <cstring>
#include <cstddef>

// Fallback cho compiler cũ không hỗ trợ builtin
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if __has_builtin(__builtin_rotateright32)
  #define ROTR32 __builtin_rotateright32
#else
  static inline uint32_t ROTR32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
  }
#endif

class DSHA256 {
public:
    static const size_t OUTPUT_SIZE = 32;

    DSHA256() {
        bytes = 0;
        initialize(s);
    }

    DSHA256 &write(const unsigned char *data, size_t len) {
        size_t bufsize = bytes % 64;
        if (bufsize && bufsize + len >= 64) {
            memcpy(buf + bufsize, data, 64 - bufsize);
            bytes += 64 - bufsize;
            data += 64 - bufsize;
            len  -= 64 - bufsize;
            transform(s, buf);
            bufsize = 0;
        }
        while (len >= 64) {
            transform(s, data);
            bytes += 64;
            data += 64;
            len -= 64;
        }
        if (len > 0) {
            memcpy(buf + bufsize, data, len);
            bytes += len;
        }
        return *this;
    }

    void finalize(unsigned char hash[OUTPUT_SIZE]) {
        const unsigned char pad[64] = {0x80};
        unsigned char sizedesc[8];
        writeBE64(sizedesc, bytes << 3);
        write(pad, 1 + ((119 - (bytes % 64)) % 64));
        write(sizedesc, 8);
        for (int i = 0; i < 8; i++) {
            writeBE32(hash + i * 4, s[i]);
        }
    }

    DSHA256 &reset() {
        bytes = 0;
        initialize(s);
        return *this;
    }

    // Hash 2 lần cho block header (double SHA-256)
    void hashBlockHeader(const unsigned char header[80], unsigned char hash[OUTPUT_SIZE]) {
        reset();
        write(header, 80);
        finalize(hash);

        unsigned char hash2[OUTPUT_SIZE];
        reset();
        write(hash, OUTPUT_SIZE);
        finalize(hash2);
        memcpy(hash, hash2, OUTPUT_SIZE);
    }

    // Lấy trạng thái (dành cho tối ưu midstate sau này)
    const uint32_t* getState() const { return s; }
    void setState(const uint32_t *state) {
        memcpy(s, state, sizeof(s));
    }
    uint64_t getBytes() const { return bytes; }
    void setBytes(uint64_t b) { bytes = b; }

private:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;

    static const uint32_t K[64];

    // Các hàm thành phần SHA-256 (giữ nguyên)
    static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint32_t Sigma0(uint32_t x) {
        return ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22);
    }
    static inline uint32_t Sigma1(uint32_t x) {
        return ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25);
    }
    static inline uint32_t sigma0(uint32_t x) {
        return ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3);
    }
    static inline uint32_t sigma1(uint32_t x) {
        return ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10);
    }

    void initialize(uint32_t *s) {
        s[0] = 0x6a09e667ul;
        s[1] = 0xbb67ae85ul;
        s[2] = 0x3c6ef372ul;
        s[3] = 0xa54ff53aul;
        s[4] = 0x510e527ful;
        s[5] = 0x9b05688cul;
        s[6] = 0x1f83d9abul;
        s[7] = 0x5be0cd19ul;
    }

    // Transform đầy đủ 64 vòng (giữ nguyên code unrolled của bạn)
    void transform(uint32_t *s, const unsigned char *chunk) {
        uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
        uint32_t e = s[4], f = s[5], g = s[6], h = s[7];
        uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
        uint32_t t1, t2;

        // Đọc message block (Big-Endian)
        w0  = readBE32(chunk + 0);
        w1  = readBE32(chunk + 4);
        w2  = readBE32(chunk + 8);
        w3  = readBE32(chunk + 12);
        w4  = readBE32(chunk + 16);
        w5  = readBE32(chunk + 20);
        w6  = readBE32(chunk + 24);
        w7  = readBE32(chunk + 28);
        w8  = readBE32(chunk + 32);
        w9  = readBE32(chunk + 36);
        w10 = readBE32(chunk + 40);
        w11 = readBE32(chunk + 44);
        w12 = readBE32(chunk + 48);
        w13 = readBE32(chunk + 52);
        w14 = readBE32(chunk + 56);
        w15 = readBE32(chunk + 60);

        // Vòng 0-15 (code unrolled gốc của bạn)
        // Vòng 0
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[0] + w0;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 1
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[1] + w1;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 2
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[2] + w2;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 3
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[3] + w3;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 4
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[4] + w4;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 5
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[5] + w5;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 6
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[6] + w6;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 7
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[7] + w7;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 8
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[8] + w8;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 9
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[9] + w9;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 10
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[10] + w10;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 11
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[11] + w11;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 12
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[12] + w12;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 13
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[13] + w13;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 14
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[14] + w14;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 15
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[15] + w15;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        // Vòng 16-63 (code unrolled gốc của bạn)
        // Vòng 16
        w0  = sigma1(w14) + w9  + sigma0(w1)  + w0;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[16] + w0;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 17
        w1  = sigma1(w15) + w10 + sigma0(w2)  + w1;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[17] + w1;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 18
        w2  = sigma1(w0)  + w11 + sigma0(w3)  + w2;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[18] + w2;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 19
        w3  = sigma1(w1)  + w12 + sigma0(w4)  + w3;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[19] + w3;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 20
        w4  = sigma1(w2)  + w13 + sigma0(w5)  + w4;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[20] + w4;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 21
        w5  = sigma1(w3)  + w14 + sigma0(w6)  + w5;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[21] + w5;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 22
        w6  = sigma1(w4)  + w15 + sigma0(w7)  + w6;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[22] + w6;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 23
        w7  = sigma1(w5)  + w0  + sigma0(w8)  + w7;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[23] + w7;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 24
        w8  = sigma1(w6)  + w1  + sigma0(w9)  + w8;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[24] + w8;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 25
        w9  = sigma1(w7)  + w2  + sigma0(w10) + w9;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[25] + w9;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 26
        w10 = sigma1(w8)  + w3  + sigma0(w11) + w10;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[26] + w10;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 27
        w11 = sigma1(w9)  + w4  + sigma0(w12) + w11;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[27] + w11;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 28
        w12 = sigma1(w10) + w5  + sigma0(w13) + w12;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[28] + w12;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 29
        w13 = sigma1(w11) + w6  + sigma0(w14) + w13;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[29] + w13;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 30
        w14 = sigma1(w12) + w7  + sigma0(w15) + w14;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[30] + w14;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 31
        w15 = sigma1(w13) + w8  + sigma0(w0)  + w15;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[31] + w15;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        // Vòng 32
        w0  = sigma1(w14) + w9  + sigma0(w1)  + w0;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[32] + w0;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 33
        w1  = sigma1(w15) + w10 + sigma0(w2)  + w1;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[33] + w1;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 34
        w2  = sigma1(w0)  + w11 + sigma0(w3)  + w2;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[34] + w2;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 35
        w3  = sigma1(w1)  + w12 + sigma0(w4)  + w3;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[35] + w3;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 36
        w4  = sigma1(w2)  + w13 + sigma0(w5)  + w4;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[36] + w4;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 37
        w5  = sigma1(w3)  + w14 + sigma0(w6)  + w5;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[37] + w5;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 38
        w6  = sigma1(w4)  + w15 + sigma0(w7)  + w6;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[38] + w6;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 39
        w7  = sigma1(w5)  + w0  + sigma0(w8)  + w7;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[39] + w7;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 40
        w8  = sigma1(w6)  + w1  + sigma0(w9)  + w8;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[40] + w8;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 41
        w9  = sigma1(w7)  + w2  + sigma0(w10) + w9;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[41] + w9;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 42
        w10 = sigma1(w8)  + w3  + sigma0(w11) + w10;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[42] + w10;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 43
        w11 = sigma1(w9)  + w4  + sigma0(w12) + w11;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[43] + w11;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 44
        w12 = sigma1(w10) + w5  + sigma0(w13) + w12;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[44] + w12;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 45
        w13 = sigma1(w11) + w6  + sigma0(w14) + w13;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[45] + w13;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 46
        w14 = sigma1(w12) + w7  + sigma0(w15) + w14;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[46] + w14;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 47
        w15 = sigma1(w13) + w8  + sigma0(w0)  + w15;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[47] + w15;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        // Vòng 48
        w0  = sigma1(w14) + w9  + sigma0(w1)  + w0;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[48] + w0;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 49
        w1  = sigma1(w15) + w10 + sigma0(w2)  + w1;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[49] + w1;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 50
        w2  = sigma1(w0)  + w11 + sigma0(w3)  + w2;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[50] + w2;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 51
        w3  = sigma1(w1)  + w12 + sigma0(w4)  + w3;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[51] + w3;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 52
        w4  = sigma1(w2)  + w13 + sigma0(w5)  + w4;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[52] + w4;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 53
        w5  = sigma1(w3)  + w14 + sigma0(w6)  + w5;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[53] + w5;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 54
        w6  = sigma1(w4)  + w15 + sigma0(w7)  + w6;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[54] + w6;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 55
        w7  = sigma1(w5)  + w0  + sigma0(w8)  + w7;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[55] + w7;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 56
        w8  = sigma1(w6)  + w1  + sigma0(w9)  + w8;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[56] + w8;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 57
        w9  = sigma1(w7)  + w2  + sigma0(w10) + w9;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[57] + w9;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 58
        w10 = sigma1(w8)  + w3  + sigma0(w11) + w10;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[58] + w10;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 59
        w11 = sigma1(w9)  + w4  + sigma0(w12) + w11;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[59] + w11;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 60
        w12 = sigma1(w10) + w5  + sigma0(w13) + w12;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[60] + w12;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 61
        w13 = sigma1(w11) + w6  + sigma0(w14) + w13;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[61] + w13;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 62
        w14 = sigma1(w12) + w7  + sigma0(w15) + w14;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[62] + w14;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        // Vòng 63
        w15 = sigma1(w13) + w8  + sigma0(w0)  + w15;
        t1 = h + Sigma1(e) + Ch(e,f,g) + K[63] + w15;
        t2 = Sigma0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        s[0] += a; s[1] += b; s[2] += c; s[3] += d;
        s[4] += e; s[5] += f; s[6] += g; s[7] += h;
    }

    static inline uint32_t readBE32(const unsigned char *ptr) {
        return __builtin_bswap32(*(uint32_t *)ptr);
    }
    static inline void writeBE32(unsigned char *ptr, uint32_t x) {
        *(uint32_t *)ptr = __builtin_bswap32(x);
    }
    static inline void writeBE64(unsigned char *ptr, uint64_t x) {
        *(uint64_t *)ptr = __builtin_bswap64(x);
    }
};

// SHA-256 constants
const uint32_t DSHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#endif
