#pragma once
#include <stdint.h>
#include <string.h>

// 纯软件 SHA-256 常量与变换宏
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// 优化的单块处理函数 - 展开循环，减少开销
inline void sha256_transform_sw(uint32_t state[8], const uint8_t data[64]) {
    uint32_t W[64];
    
    // 加载并转换前 16 个字 (大端序转小端序)
    W[0]  = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    W[1]  = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) | ((uint32_t)data[6] << 8) | (uint32_t)data[7];
    W[2]  = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | (uint32_t)data[11];
    W[3]  = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) | ((uint32_t)data[14] << 8) | (uint32_t)data[15];
    W[4]  = ((uint32_t)data[16] << 24) | ((uint32_t)data[17] << 16) | ((uint32_t)data[18] << 8) | (uint32_t)data[19];
    W[5]  = ((uint32_t)data[20] << 24) | ((uint32_t)data[21] << 16) | ((uint32_t)data[22] << 8) | (uint32_t)data[23];
    W[6]  = ((uint32_t)data[24] << 24) | ((uint32_t)data[25] << 16) | ((uint32_t)data[26] << 8) | (uint32_t)data[27];
    W[7]  = ((uint32_t)data[28] << 24) | ((uint32_t)data[29] << 16) | ((uint32_t)data[30] << 8) | (uint32_t)data[31];
    W[8]  = ((uint32_t)data[32] << 24) | ((uint32_t)data[33] << 16) | ((uint32_t)data[34] << 8) | (uint32_t)data[35];
    W[9]  = ((uint32_t)data[36] << 24) | ((uint32_t)data[37] << 16) | ((uint32_t)data[38] << 8) | (uint32_t)data[39];
    W[10] = ((uint32_t)data[40] << 24) | ((uint32_t)data[41] << 16) | ((uint32_t)data[42] << 8) | (uint32_t)data[43];
    W[11] = ((uint32_t)data[44] << 24) | ((uint32_t)data[45] << 16) | ((uint32_t)data[46] << 8) | (uint32_t)data[47];
    W[12] = ((uint32_t)data[48] << 24) | ((uint32_t)data[49] << 16) | ((uint32_t)data[50] << 8) | (uint32_t)data[51];
    W[13] = ((uint32_t)data[52] << 24) | ((uint32_t)data[53] << 16) | ((uint32_t)data[54] << 8) | (uint32_t)data[55];
    W[14] = ((uint32_t)data[56] << 24) | ((uint32_t)data[57] << 16) | ((uint32_t)data[58] << 8) | (uint32_t)data[59];
    W[15] = ((uint32_t)data[60] << 24) | ((uint32_t)data[61] << 16) | ((uint32_t)data[62] << 8) | (uint32_t)data[63];
    
    // 扩展消息调度表
    for (int i = 16; i < 64; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // 完全展开 64 轮循环，消除循环开销
    #define ROUND(i) do { \
        uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
        uint32_t t2 = Sigma0(a) + Maj(a, b, c); \
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; \
    } while(0)

    ROUND(0);  ROUND(1);  ROUND(2);  ROUND(3);  ROUND(4);  ROUND(5);  ROUND(6);  ROUND(7);
    ROUND(8);  ROUND(9);  ROUND(10); ROUND(11); ROUND(12); ROUND(13); ROUND(14); ROUND(15);
    ROUND(16); ROUND(17); ROUND(18); ROUND(19); ROUND(20); ROUND(21); ROUND(22); ROUND(23);
    ROUND(24); ROUND(25); ROUND(26); ROUND(27); ROUND(28); ROUND(29); ROUND(30); ROUND(31);
    ROUND(32); ROUND(33); ROUND(34); ROUND(35); ROUND(36); ROUND(37); ROUND(38); ROUND(39);
    ROUND(40); ROUND(41); ROUND(42); ROUND(43); ROUND(44); ROUND(45); ROUND(46); ROUND(47);
    ROUND(48); ROUND(49); ROUND(50); ROUND(51); ROUND(52); ROUND(53); ROUND(54); ROUND(55);
    ROUND(56); ROUND(57); ROUND(58); ROUND(59); ROUND(60); ROUND(61); ROUND(62); ROUND(63);

    #undef ROUND

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// 专门针对 80 字节 Bitcoin Header 的双重 SHA-256 软件模拟 - 优化版本
inline void sha256_double_sw(const uint8_t* header, uint8_t* out_hash) {
    // 第一次哈希 (80 字节 = 64 字节全块 + 16 字节剩余)
    uint32_t s1[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    
    // 直接内联第一块处理
    sha256_transform_sw(s1, header);
    
    // 第二块预处理 (16 字节数据 + 填充)
    alignas(64) uint8_t block2[64] = {0};
    memcpy(block2, header + 64, 16);
    block2[16] = 0x80;
    // 80 字节 = 640 bits = 0x280 (写在末尾)
    block2[62] = 0x02; block2[63] = 0x80; 
    sha256_transform_sw(s1, block2);

    // 输出中间哈希 (小端序)
    uint8_t hash1[32];
    for (int i = 0; i < 8; i++) {
        hash1[i*4] = s1[i] >> 24; hash1[i*4+1] = s1[i] >> 16;
        hash1[i*4+2] = s1[i] >> 8; hash1[i*4+3] = s1[i];
    }

    // 第二次哈希 (处理 32 字节哈希结果)
    uint32_t s2[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    alignas(64) uint8_t block3[64] = {0};
    memcpy(block3, hash1, 32);
    block3[32] = 0x80;
    // 32 字节 = 256 bits = 0x100
    block3[62] = 0x01; block3[63] = 0x00;
    sha256_transform_sw(s2, block3);

    // 输出最终哈希 (小端序)
    for (int i = 0; i < 8; i++) {
        out_hash[i*4] = s2[i] >> 24; out_hash[i*4+1] = s2[i] >> 16;
        out_hash[i*4+2] = s2[i] >> 8; out_hash[i*4+3] = s2[i];
    }
}
