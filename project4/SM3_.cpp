#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <array>

// SM3密码杂凑算法实现类
class SM3Hash {
public:
    // 计算字符串的哈希值
    std::vector<uint8_t> compute(const std::string& text) {
        return compute(reinterpret_cast<const uint8_t*>(text.c_str()), text.length());
    }

    // 计算字节数组的哈希值
    std::vector<uint8_t> compute(const uint8_t* data, size_t len) {
        // 初始化哈希缓冲区
        std::array<uint32_t, 8> buffer = {
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        };

        // 对输入数据进行填充处理
        auto padded_data = add_padding(data, len);

        // 按512位(64字节)分组处理
        for (size_t i = 0; i < padded_data.size(); i += BLOCK_BYTES) {
            process_block(buffer, &padded_data[i]);
        }

        // 将缓冲区数据转换为字节序列
        std::vector<uint8_t> result(DIGEST_BYTES);
        for (size_t i = 0; i < buffer.size(); ++i) {
            result[i*4]   = static_cast<uint8_t>(buffer[i] >> 24);
            result[i*4+1] = static_cast<uint8_t>(buffer[i] >> 16);
            result[i*4+2] = static_cast<uint8_t>(buffer[i] >> 8);
            result[i*4+3] = static_cast<uint8_t>(buffer[i]);
        }

        return result;
    }

private:
    static constexpr size_t BLOCK_BYTES = 64;   // 分组大小(字节)
    static constexpr size_t DIGEST_BYTES = 32;  // 哈希结果长度(字节)

    // 循环左移操作
    static uint32_t left_rotate(uint32_t value, uint32_t shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    // 置换函数P0
    static uint32_t permute0(uint32_t x) {
        return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
    }

    // 置换函数P1
    static uint32_t permute1(uint32_t x) {
        return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
    }

    // 常量Tj生成
    static constexpr uint32_t get_constant(int j) {
        return j < 16 ? 0x79CC4519 : 0x7A879D8A;
    }

    // 布尔函数FF
    static uint32_t bool_func_ff(uint32_t x, uint32_t y, uint32_t z, int j) {
        return j < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);
    }

    // 布尔函数GG
    static uint32_t bool_func_gg(uint32_t x, uint32_t y, uint32_t z, int j) {
        return j < 16 ? x ^ y ^ z : (x & y) | ((~x) & z);
    }

    // 数据填充处理
    std::vector<uint8_t> add_padding(const uint8_t* data, size_t len) const {
        const size_t bit_len = len * 8;
        std::vector<uint8_t> padded(data, data + len);

        // 添加结束标志位'1'
        padded.push_back(0x80);

        // 填充0直到满足长度要求
        while ((padded.size() * 8 + 64) % 512 != 0) {
            padded.push_back(0x00);
        }

        // 添加原始数据长度(64位大端格式)
        for (int i = 7; i >= 0; --i) {
            padded.push_back(static_cast<uint8_t>(bit_len >> (8 * i)));
        }

        return padded;
    }

    // 消息扩展
    void expand_message(const uint8_t* block, std::array<uint32_t, 68>& w,
                       std::array<uint32_t, 64>& w_prime) const {
        // 前16个字直接从消息块转换
        for (int j = 0; j < 16; ++j) {
            w[j] = (static_cast<uint32_t>(block[j*4]) << 24) |
                   (static_cast<uint32_t>(block[j*4+1]) << 16) |
                   (static_cast<uint32_t>(block[j*4+2]) << 8) |
                   static_cast<uint32_t>(block[j*4+3]);
        }

        // 生成剩余的W值
        for (int j = 16; j < 68; ++j) {
            w[j] = permute1(w[j-16] ^ w[j-9] ^ left_rotate(w[j-3], 15)) ^
                   left_rotate(w[j-13], 7) ^ w[j-6];
        }

        // 生成W'序列
        for (int j = 0; j < 64; ++j) {
            w_prime[j] = w[j] ^ w[j+4];
        }
    }

    // 压缩函数
    void process_block(std::array<uint32_t, 8>& buffer, const uint8_t* block) const {
        std::array<uint32_t, 68> w;
        std::array<uint32_t, 64> w_prime;
        expand_message(block, w, w_prime);

        // 初始化压缩变量
        uint32_t a = buffer[0], b = buffer[1], c = buffer[2], d = buffer[3];
        uint32_t e = buffer[4], f = buffer[5], g = buffer[6], h = buffer[7];

        // 64轮压缩迭代
        for (int j = 0; j < 64; ++j) {
            const uint32_t t_j = left_rotate(get_constant(j), j);
            const uint32_t ss1 = left_rotate(((left_rotate(a, 12) + e + t_j) & 0xFFFFFFFF), 7);
            const uint32_t ss2 = ss1 ^ left_rotate(a, 12);
            const uint32_t tt1 = (bool_func_ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF;
            const uint32_t tt2 = (bool_func_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF;

            // 更新压缩变量
            d = c;
            c = left_rotate(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = left_rotate(f, 19);
            f = e;
            e = permute0(tt2);
        }

        // 更新缓冲区
        buffer[0] ^= a; buffer[1] ^= b; buffer[2] ^= c; buffer[3] ^= d;
        buffer[4] ^= e; buffer[5] ^= f; buffer[6] ^= g; buffer[7] ^= h;
    }
};

// 字节数组转十六进制字符串
std::string to_hex_string(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

int main() {
    SM3Hash sm3;

    // 测试用例集合
    const std::vector<std::pair<std::string, std::string>> test_cases = {
        {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
        {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
        {"HelloSM3", "36065686c1859012d3b504ecee7ae52e5f0fdf3089a0854811f613f77599a4cd"}
    };

    // 执行测试
    for (const auto& [input, expected] : test_cases) {
        auto hash_result = sm3.compute(input);
        std::string hex_result = to_hex_string(hash_result);

        std::cout << "输入: \"" << input << "\"\n"
                  << "计算结果: " << hex_result << "\n"
                  << "预期结果: " << expected << "\n"
                  << "匹配: " << (hex_result == expected) << "\n\n";
    }

    return 0;
}
    