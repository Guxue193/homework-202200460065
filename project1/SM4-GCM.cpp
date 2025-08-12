#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>
using namespace std;

// --- SM4相关常量和函数 ---
static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t L(uint32_t x) {
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
}

uint32_t T_prime(uint32_t x) {
    uint8_t a[4] = {
        static_cast<uint8_t>(x >> 24),
        static_cast<uint8_t>(x >> 16),
        static_cast<uint8_t>(x >> 8),
        static_cast<uint8_t>(x)
    };
    for (int i = 0; i < 4; ++i)
        a[i] = SM4_SBOX[a[i]];
    uint32_t B = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    return B ^ rotl(B, 13) ^ rotl(B, 23);
}

void key_schedule(const uint32_t key[4], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; ++i)
        K[i] = key[i] ^ FK[i];
    for (int i = 0; i < 32; ++i)
        K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
    memcpy(rk, &K[4], 32 * sizeof(uint32_t));
}

uint32_t T_lookup(uint32_t x) {
    // 简化版本，直接使用T_prime，避免初始化T-box
    return T_prime(x);
}

void sm4_crypt(uint32_t block[4], const uint32_t rk[32], bool enc = true) {
    uint32_t X[36];
    memcpy(X, block, 4 * sizeof(uint32_t));
    for (int i = 0; i < 32; ++i) {
        int r = enc ? i : 31 - i;
        X[i + 4] = X[i] ^ T_lookup(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[r]);
    }
    for (int i = 0; i < 4; ++i)
        block[i] = X[35 - i];
}

// --- 128位数的异或 ---
inline void xor_128(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; ++i) out[i] = a[i] ^ b[i];
}

// --- 128位GF(2^128)乘法（GHASH用）---
// 简单移位乘法，基于RFC 4493中GF(2^128)的定义
void gf_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]) {
    uint8_t V[16];
    memcpy(V, Y, 16);
    memset(Z, 0, 16);

    for (int i = 0; i < 128; ++i) {
        int byte = i / 8;
        int bit = 7 - (i % 8);
        if ((X[byte] >> bit) & 1) {
            for (int j = 0; j < 16; ++j)
                Z[j] ^= V[j];
        }
        // 右移V（大端）
        bool lsb = (V[15] & 1) != 0;
        for (int j = 15; j > 0; --j)
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        V[0] >>= 1;
        if (lsb) {
            // 多项式: x^128 + x^7 + x^2 + x + 1 对应的R值
            V[0] ^= 0xe1;
        }
    }
}

// --- GHASH结构 ---
struct GHASH {
    uint8_t H[16];
    uint8_t Y[16]; // 当前状态

    void init(const uint8_t H_in[16]) {
        memcpy(H, H_in, 16);
        memset(Y, 0, 16);
    }

    void update(const uint8_t data[16], size_t len = 16) {
        // 假设data长度为16，调用时外部负责padding
        xor_128(Y, Y, data);
        uint8_t tmp[16];
        gf_mul(Y, H, tmp);
        memcpy(Y, tmp, 16);
    }

    // 长度为字节数，计算最后的认证值
    // A_len、C_len长度单位字节，最后填充16字节结构存入tag
    void finalize(size_t A_len, size_t C_len, uint8_t tag[16]) {
        uint8_t len_block[16] = { 0 };
        // 左8字节：A_len*8 (bit长度) 大端
        uint64_t alen_bits = A_len * 8ULL;
        for (int i = 0; i < 8; ++i)
            len_block[7 - i] = (alen_bits >> (8 * i)) & 0xFF;
        // 右8字节：C_len*8 (bit长度) 大端
        uint64_t clen_bits = C_len * 8ULL;
        for (int i = 0; i < 8; ++i)
            len_block[15 - i] = (clen_bits >> (8 * i)) & 0xFF;

        update(len_block, 16);
        memcpy(tag, Y, 16);
    }
};

// --- 计数器模式加密 ---
// 输入：nonce计数器初始值16字节，轮密钥rk，明文in，输出out，长度len字节
void ctr_crypt(const uint8_t nonce[16], const uint32_t rk[32], const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t counter[16];
    memcpy(counter, nonce, 16);
    uint32_t block[4];
    size_t blocks = len / 16;
    size_t rem = len % 16;

    for (size_t i = 0; i < blocks; ++i) {
        memcpy(block, counter, 16);
        sm4_crypt(block, rk, true);

        uint8_t keystream[16];
        for (int j = 0; j < 4; ++j) {
            keystream[4 * j] = (block[j] >> 24) & 0xFF;
            keystream[4 * j + 1] = (block[j] >> 16) & 0xFF;
            keystream[4 * j + 2] = (block[j] >> 8) & 0xFF;
            keystream[4 * j + 3] = block[j] & 0xFF;
        }

        for (int j = 0; j < 16; ++j)
            out[i * 16 + j] = in[i * 16 + j] ^ keystream[j];

        // 计数器加1（仅最低64位）
        for (int j = 15; j >= 8; --j) {
            if (++counter[j] != 0)
                break;
        }
    }

    if (rem) {
        memcpy(block, counter, 16);
        sm4_crypt(block, rk, true);
        uint8_t keystream[16];
        for (int j = 0; j < 4; ++j) {
            keystream[4 * j] = (block[j] >> 24) & 0xFF;
            keystream[4 * j + 1] = (block[j] >> 16) & 0xFF;
            keystream[4 * j + 2] = (block[j] >> 8) & 0xFF;
            keystream[4 * j + 3] = block[j] & 0xFF;
        }
        for (size_t j = 0; j < rem; ++j)
            out[blocks * 16 + j] = in[blocks * 16 + j] ^ keystream[j];
    }
}

// --- SM4-GCM加密 ---
void sm4_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext, uint8_t tag[16]) {

    uint32_t key_u32[4];
    for (int i = 0; i < 4; ++i)
        key_u32[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];

    uint32_t rk[32];
    key_schedule(key_u32, rk);

    // 计算H = SM4_Encrypt(0)
    uint32_t zero_block[4] = { 0 };
    sm4_crypt(zero_block, rk, true);
    uint8_t H[16];
    for (int i = 0; i < 4; ++i) {
        H[4 * i] = (zero_block[i] >> 24) & 0xFF;
        H[4 * i + 1] = (zero_block[i] >> 16) & 0xFF;
        H[4 * i + 2] = (zero_block[i] >> 8) & 0xFF;
        H[4 * i + 3] = zero_block[i] & 0xFF;
    }

    // IV拼成计数器初值 J0 = IV || 0x00000001
    uint8_t J0[16] = { 0 };
    memcpy(J0, iv, 12);
    J0[15] = 1;

    // 计数器初值 +1 用于加密计数器
    uint8_t ctr0[16];
    memcpy(ctr0, J0, 16);
    for (int j = 15; j >= 8; --j) {
        if (++ctr0[j] != 0)
            break;
    }

    // CTR模式加密
    ctr_crypt(ctr0, rk, plaintext, ciphertext, pt_len);

    // 计算认证TAG
    GHASH ghash;
    ghash.init(H);

    // AAD 认证（填充16字节块）
    size_t aad_blocks = aad_len / 16;
    size_t aad_rem = aad_len % 16;
    for (size_t i = 0; i < aad_blocks; ++i)
        ghash.update(aad + i * 16);
    if (aad_rem) {
        uint8_t last[16] = { 0 };
        memcpy(last, aad + aad_blocks * 16, aad_rem);
        ghash.update(last);
    }

    // 密文认证
    size_t ct_blocks = pt_len / 16;
    size_t ct_rem = pt_len % 16;
    for (size_t i = 0; i < ct_blocks; ++i)
        ghash.update(ciphertext + i * 16);
    if (ct_rem) {
        uint8_t last[16] = { 0 };
        memcpy(last, ciphertext + ct_blocks * 16, ct_rem);
        ghash.update(last);
    }

    // 认证长度域
    ghash.finalize(aad_len, pt_len, tag);

    // 最后计算TAG = GHASH ^ SM4(J0)
    uint32_t J0_enc[4];
    for (int i = 0; i < 4; ++i)
        J0_enc[i] = (J0[4 * i] << 24) | (J0[4 * i + 1] << 16) | (J0[4 * i + 2] << 8) | J0[4 * i + 3];
    sm4_crypt(J0_enc, rk, true);
    uint8_t s[16];
    for (int i = 0; i < 4; ++i) {
        s[4 * i] = (J0_enc[i] >> 24) & 0xFF;
        s[4 * i + 1] = (J0_enc[i] >> 16) & 0xFF;
        s[4 * i + 2] = (J0_enc[i] >> 8) & 0xFF;
        s[4 * i + 3] = J0_enc[i] & 0xFF;
    }
    xor_128(tag, tag, s);
}

// --- SM4-GCM解密 ---
// 返回true表示认证通过，否则false
bool sm4_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t* plaintext) {

    uint32_t key_u32[4];
    for (int i = 0; i < 4; ++i)
        key_u32[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];

    uint32_t rk[32];
    key_schedule(key_u32, rk);

    // 计算H
    uint32_t zero_block[4] = { 0 };
    sm4_crypt(zero_block, rk, true);
    uint8_t H[16];
    for (int i = 0; i < 4; ++i) {
        H[4 * i] = (zero_block[i] >> 24) & 0xFF;
        H[4 * i + 1] = (zero_block[i] >> 16) & 0xFF;
        H[4 * i + 2] = (zero_block[i] >> 8) & 0xFF;
        H[4 * i + 3] = zero_block[i] & 0xFF;
    }

    uint8_t J0[16] = { 0 };
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t ctr0[16];
    memcpy(ctr0, J0, 16);
    for (int j = 15; j >= 8; --j) {
        if (++ctr0[j] != 0)
            break;
    }

    // 解密
    ctr_crypt(ctr0, rk, ciphertext, plaintext, ct_len);

    // 认证计算
    GHASH ghash;
    ghash.init(H);

    size_t aad_blocks = aad_len / 16;
    size_t aad_rem = aad_len % 16;
    for (size_t i = 0; i < aad_blocks; ++i)
        ghash.update(aad + i * 16);
    if (aad_rem) {
        uint8_t last[16] = { 0 };
        memcpy(last, aad + aad_blocks * 16, aad_rem);
        ghash.update(last);
    }

    size_t ct_blocks = ct_len / 16;
    size_t ct_rem = ct_len % 16;
    for (size_t i = 0; i < ct_blocks; ++i)
        ghash.update(ciphertext + i * 16);
    if (ct_rem) {
        uint8_t last[16] = { 0 };
        memcpy(last, ciphertext + ct_blocks * 16, ct_rem);
        ghash.update(last);
    }

    uint8_t calc_tag[16];
    ghash.finalize(aad_len, ct_len, calc_tag);

    uint32_t J0_enc[4];
    for (int i = 0; i < 4; ++i)
        J0_enc[i] = (J0[4 * i] << 24) | (J0[4 * i + 1] << 16) | (J0[4 * i + 2] << 8) | J0[4 * i + 3];
    sm4_crypt(J0_enc, rk, true);
    uint8_t s[16];
    for (int i = 0; i < 4; ++i) {
        s[4 * i] = (J0_enc[i] >> 24) & 0xFF;
        s[4 * i + 1] = (J0_enc[i] >> 16) & 0xFF;
        s[4 * i + 2] = (J0_enc[i] >> 8) & 0xFF;
        s[4 * i + 3] = J0_enc[i] & 0xFF;
    }
    xor_128(calc_tag, calc_tag, s);

    // 比较TAG
    bool valid = true;
    for (int i = 0; i < 16; ++i) {
        if (calc_tag[i] != tag[i]) {
            valid = false;
            break;
        }
    }
    return valid;
}

// --- 测试 ---

void print_hex(const uint8_t* data, size_t len, const string& label) {
    cout << label << ": ";
    for (size_t i = 0; i < len; ++i)
        cout << hex << setw(2) << setfill('0') << (int)data[i];
    cout << dec << endl;
}

void test_gcm_correctness() {
    cout << "=== SM4-GCM Correctness Test ===\n";

    uint8_t key[16] = { 0 };
    uint8_t iv[12] = { 0 };
    uint8_t plaintext[32] = { 0 };
    uint8_t aad[20] = { 0 };

    for (int i = 0; i < 16; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) iv[i] = i + 1;
    for (int i = 0; i < 32; ++i) plaintext[i] = i + 0x10;
    for (int i = 0; i < 20; ++i) aad[i] = i + 0x20;

    uint8_t ciphertext[32];
    uint8_t tag[16];

    sm4_gcm_encrypt(key, iv, plaintext, 32, aad, 20, ciphertext, tag);

    print_hex(plaintext, 32, "Plaintext");
    print_hex(ciphertext, 32, "Ciphertext");
    print_hex(tag, 16, "Tag");

    uint8_t decrypted[32];
    bool valid = sm4_gcm_decrypt(key, iv, ciphertext, 32, aad, 20, tag, decrypted);

    print_hex(decrypted, 32, "Decrypted");
    cout << "Authentication " << (valid ? "Passed" : "Failed") << endl;
}

void test_gcm_performance() {
    cout << "\n=== SM4-GCM Performance Test ===\n";
    uint8_t key[16] = { 0 };
    uint8_t iv[12] = { 0 };
    for (int i = 0; i < 16; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) iv[i] = i + 1;

    size_t size = 1024 * 1024; // 1MB
    vector<uint8_t> plaintext(size, 0x55);
    vector<uint8_t> ciphertext(size);
    vector<uint8_t> decrypted(size);
    vector<uint8_t> aad(32, 0xaa);
    uint8_t tag[16];

    auto start = chrono::high_resolution_clock::now();
    sm4_gcm_encrypt(key, iv, plaintext.data(), size, aad.data(), aad.size(), ciphertext.data(), tag);
    auto mid = chrono::high_resolution_clock::now();
    bool valid = sm4_gcm_decrypt(key, iv, ciphertext.data(), size, aad.data(), aad.size(), tag, decrypted.data());
    auto end = chrono::high_resolution_clock::now();

    chrono::duration<double> enc_time = mid - start;
    chrono::duration<double> dec_time = end - mid;

    cout << "Encryption time for 1MB: " << enc_time.count() << " seconds\n";
    cout << "Decryption time for 1MB: " << dec_time.count() << " seconds\n";

    bool equal = memcmp(plaintext.data(), decrypted.data(), size) == 0;
    cout << "Decryption correctness: " << (equal ? "Passed" : "Failed") << endl;
    cout << "Authentication " << (valid ? "Passed" : "Failed") << endl;
}

int main() {
    test_gcm_correctness();
    test_gcm_performance();
    system("pause");
    return 0;
}
