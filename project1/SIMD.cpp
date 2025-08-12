#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <chrono>
#include <emmintrin.h>

using namespace std;

// SM4算法S盒定义
static const unsigned char SM4_SUB_BOX[256] = {
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

// 系统参数与轮密钥参数
const uint32_t SYS_PARAMS[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
const uint32_t ROUND_KEY_PARAMS[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// T盒存储结构
uint32_t T_BOX0[256], T_BOX1[256], T_BOX2[256], T_BOX3[256];

// 循环左移操作
inline uint32_t left_rotate(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

// L变换实现
uint32_t L_transform(uint32_t value) {
    return value ^ left_rotate(value, 2) ^ left_rotate(value, 10) ^ 
           left_rotate(value, 18) ^ left_rotate(value, 24);
}

// 初始化T盒
void initialize_tbox() {
    for (int i = 0; i < 256; ++i) {
        unsigned char s_val = SM4_SUB_BOX[i];
        uint32_t trans_val = L_transform(static_cast<uint32_t>(s_val) << 24);
        T_BOX0[i] = trans_val;
        T_BOX1[i] = left_rotate(trans_val, 8);
        T_BOX2[i] = left_rotate(trans_val, 16);
        T_BOX3[i] = left_rotate(trans_val, 24);
    }
}

// T函数查表实现
inline uint32_t T_function(uint32_t input) {
    return T_BOX0[(input >> 24) & 0xff] ^ T_BOX1[(input >> 16) & 0xff] ^
           T_BOX2[(input >> 8) & 0xff] ^ T_BOX3[input & 0xff];
}

// 密钥扩展中的T'函数
uint32_t T_prime_transform(uint32_t input) {
    unsigned char bytes[4] = {
        static_cast<unsigned char>(input >> 24),
        static_cast<unsigned char>(input >> 16),
        static_cast<unsigned char>(input >> 8),
        static_cast<unsigned char>(input)
    };
    
    // S盒置换
    for (int i = 0; i < 4; ++i) {
        bytes[i] = SM4_SUB_BOX[bytes[i]];
    }
    
    uint32_t transformed = (static_cast<uint32_t>(bytes[0]) << 24) |
                           (static_cast<uint32_t>(bytes[1]) << 16) |
                           (static_cast<uint32_t>(bytes[2]) << 8) |
                           static_cast<uint32_t>(bytes[3]);
                           
    return transformed ^ left_rotate(transformed, 13) ^ left_rotate(transformed, 23);
}

// 生成轮密钥
void generate_round_keys(const uint32_t key[4], uint32_t round_keys[32]) {
    uint32_t key_regs[36];
    
    // 初始密钥处理
    for (int i = 0; i < 4; ++i) {
        key_regs[i] = key[i] ^ SYS_PARAMS[i];
    }
    
    // 轮密钥计算
    for (int i = 0; i < 32; ++i) {
        key_regs[i + 4] = key_regs[i] ^ T_prime_transform(
            key_regs[i + 1] ^ key_regs[i + 2] ^ key_regs[i + 3] ^ ROUND_KEY_PARAMS[i]
        );
    }
    
    memcpy(round_keys, &key_regs[4], 32 * sizeof(uint32_t));
}

// SM4加解密核心函数
void sm4_process_block(uint32_t block[4], const uint32_t round_keys[32], bool encrypt = true) {
    uint32_t state[36];
    memcpy(state, block, 4 * sizeof(uint32_t));
    
    // 32轮迭代
    for (int i = 0; i < 32; ++i) {
        int round_idx = encrypt ? i : 31 - i;
        state[i + 4] = state[i] ^ T_function(
            state[i + 1] ^ state[i + 2] ^ state[i + 3] ^ round_keys[round_idx]
        );
    }
    
    // 输出变换
    for (int i = 0; i < 4; ++i) {
        block[i] = state[35 - i];
    }
}

// SIMD并行加密（一次处理4个块）
void sm4_simd_encrypt4(uint32_t output[4][4], const uint32_t input[4][4], const uint32_t round_keys[32]) {
    uint32_t block_states[4][36];
    
    // 初始化状态
    for (int b = 0; b < 4; ++b) {
        memcpy(block_states[b], input[b], 4 * sizeof(uint32_t));
    }
    
    // 并行轮处理
    for (int i = 0; i < 32; ++i) {
        for (int b = 0; b < 4; ++b) {
            uint32_t temp = block_states[b][i + 1] ^ block_states[b][i + 2] ^ 
                           block_states[b][i + 3] ^ round_keys[i];
            block_states[b][i + 4] = block_states[b][i] ^ T_function(temp);
        }
    }
    
    // 结果输出
    for (int b = 0; b < 4; ++b) {
        for (int j = 0; j < 4; ++j) {
            output[b][j] = block_states[b][35 - j];
        }
    }
}

// 打印数据块
void display_block(const string& title, const uint32_t block[4]) {
    cout << title << ": ";
    for (int i = 0; i < 4; ++i) {
        cout << hex << setw(8) << setfill('0') << block[i] << " ";
    }
    cout << dec << endl;
}

// 基础正确性测试
void verify_basic_function() {
    uint32_t plaintext[4] = {0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00};
    uint32_t secret_key[4] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff};
    uint32_t ciphertext[4], decrypted[4], round_keys[32];
    
    generate_round_keys(secret_key, round_keys);
    
    // 加密
    memcpy(ciphertext, plaintext, sizeof(ciphertext));
    sm4_process_block(ciphertext, round_keys, true);
    
    // 解密
    memcpy(decrypted, ciphertext, sizeof(decrypted));
    sm4_process_block(decrypted, round_keys, false);
    
    // 输出结果
    display_block("明文", plaintext);
    display_block("密文", ciphertext);
    display_block("解密后", decrypted);
    
    // 验证结果
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        cout << "正确性验证: 通过" << endl;
    } else {
        cout << "正确性验证: 失败" << endl;
    }
}

// SIMD正确性测试
void verify_simd_function() {
    uint32_t round_keys[32];
    uint32_t secret_key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    generate_round_keys(secret_key, round_keys);
    
    uint32_t test_inputs[4][4], simd_output[4][4], normal_output[4][4];
    
    // 生成测试数据
    for (int b = 0; b < 4; ++b) {
        for (int i = 0; i < 4; ++i) {
            test_inputs[b][i] = 0x11111111 * (b + 1) + i;
        }
    }
    
    // SIMD加密
    sm4_simd_encrypt4(simd_output, test_inputs, round_keys);
    
    // 普通加密（作为对照）
    for (int b = 0; b < 4; ++b) {
        memcpy(normal_output[b], test_inputs[b], sizeof(normal_output[b]));
        sm4_process_block(normal_output[b], round_keys, true);
    }
    
    // 比较结果
    bool result_match = true;
    for (int b = 0; b < 4; ++b) {
        if (memcmp(simd_output[b], normal_output[b], 16) != 0) {
            result_match = false;
            break;
        }
    }
    
    cout << "[SIMD正确性测试] " << (result_match ? "通过" : "失败") << endl;
}

// SIMD性能测试
void test_simd_performance() {
    const int TEST_COUNT = 1000000;
    uint32_t round_keys[32];
    uint32_t secret_key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    generate_round_keys(secret_key, round_keys);
    
    // 测试数据
    uint32_t test_blocks[4][4] = {
        {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
        {0x01234567, 0x89abcdef, 0xfedcba98,