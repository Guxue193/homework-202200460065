#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>

// SM3密码杂凑算法实现类
class SM3HashAlgorithm {
public:
    // 计算字符串的哈希值
    std::vector<uint8_t> calculateHash(const std::string& text) {
        return calculateHash(reinterpret_cast<const uint8_t*>(text.c_str()), text.length());
    }

    // 计算字节数组的哈希值
    std::vector<uint8_t> calculateHash(const uint8_t* data, size_t len) {
        // 初始化哈希缓冲区
        uint32_t hashBuffer[8] = {
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        };

        // 对输入数据进行填充处理
        std::vector<uint8_t> paddedData = addPadding(data, len);

        // 按512位(64字节)分组处理数据
        for (size_t i = 0; i < paddedData.size(); i += 64) {
            processBlock(hashBuffer, &paddedData[i]);
        }

        // 将哈希结果转换为字节数组
        std::vector<uint8_t> hashResult(32);
        for (int i = 0; i < 8; i++) {
            hashResult[i*4]   = (hashBuffer[i] >> 24) & 0xFF;
            hashResult[i*4+1] = (hashBuffer[i] >> 16) & 0xFF;
            hashResult[i*4+2] = (hashBuffer[i] >> 8)  & 0xFF;
            hashResult[i*4+3] = hashBuffer[i] & 0xFF;
        }

        return hashResult;
    }

private:
    // 循环左移操作
    uint32_t leftRotate(uint32_t value, uint32_t shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    // 置换函数P0
    uint32_t permute0(uint32_t value) {
        return value ^ leftRotate(value, 9) ^ leftRotate(value, 17);
    }

    // 置换函数P1
    uint32_t permute1(uint32_t value) {
        return value ^ leftRotate(value, 15) ^ leftRotate(value, 23);
    }

    // 常量生成函数
    uint32_t getConstant(int index) {
        return index < 16 ? 0x79CC4519 : 0x7A879D8A;
    }

    // 布尔函数FF
    uint32_t boolFunctionFF(uint32_t x, uint32_t y, uint32_t z, int index) {
        return index < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);
    }

    // 布尔函数GG
    uint32_t boolFunctionGG(uint32_t x, uint32_t y, uint32_t z, int index) {
        return index < 16 ? x ^ y ^ z : (x & y) | ((~x) & z);
    }

    // 数据填充处理
    std::vector<uint8_t> addPadding(const uint8_t* data, size_t len) {
        size_t bitLength = len * 8;
        std::vector<uint8_t> paddedData(data, data + len);

        // 添加结束标志位
        paddedData.push_back(0x80);

        // 填充0直到满足长度要求
        while ((paddedData.size() * 8 + 64) % 512 != 0) {
            paddedData.push_back(0x00);
        }

        // 添加原始数据长度(64位)
        for (int i = 7; i >= 0; i--) {
            paddedData.push_back((bitLength >> (8 * i)) & 0xFF);
        }

        return paddedData;
    }

    // 消息扩展
    void expandMessage(const uint8_t* block, uint32_t W[68], uint32_t W_[64]) {
        // 前16个字直接从消息块转换
        for (int j = 0; j < 16; j++) {
            W[j] = (block[j*4] << 24) | (block[j*4+1] << 16) |
                   (block[j*4+2] << 8) | block[j*4+3];
        }

        // 生成剩余的W值
        for (int j = 16; j < 68; j++) {
            W[j] = permute1(W[j-16] ^ W[j-9] ^ leftRotate(W[j-3], 15)) ^
                   leftRotate(W[j-13], 7) ^ W[j-6];
        }

        // 生成W'序列
        for (int j = 0; j < 64; j++) {
            W_[j] = W[j] ^ W[j+4];
        }
    }

    // 压缩函数
    void processBlock(uint32_t hashBuffer[8], const uint8_t* block) {
        uint32_t W[68], W_[64];
        expandMessage(block, W, W_);

        // 初始化压缩寄存器
        uint32_t A = hashBuffer[0], B = hashBuffer[1], C = hashBuffer[2], D = hashBuffer[3];
        uint32_t E = hashBuffer[4], F = hashBuffer[5], G = hashBuffer[6], H = hashBuffer[7];

        // 64轮压缩迭代
        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = leftRotate((leftRotate(A, 12) + E + leftRotate(getConstant(j), j)) & 0xFFFFFFFF, 7);
            uint32_t SS2 = SS1 ^ leftRotate(A, 12);
            uint32_t TT1 = (boolFunctionFF(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF;
            uint32_t TT2 = (boolFunctionGG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;

            // 更新压缩变量
            D = C;
            C = leftRotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = leftRotate(F, 19);
            F = E;
            E = permute0(TT2);
        }

        // 更新哈希缓冲区
        hashBuffer[0] ^= A; hashBuffer[1] ^= B; hashBuffer[2] ^= C; hashBuffer[3] ^= D;
        hashBuffer[4] ^= E; hashBuffer[5] ^= F; hashBuffer[6] ^= G; hashBuffer[7] ^= H;
    }
};

// 字节数组转十六进制字符串
std::string convertToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

int main() {
    SM3HashAlgorithm sm3;

    // 测试用例
    struct HashTestCase {
        std::string inputText;
        std::string expectedHash;
    } testCases[] = {
        {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
        {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
        {"HelloSM3", "36065686c1859012d3b504ecee7ae52e5f0fdf3089a0854811f613f77599a4cd"}
    };

    // 执行测试
    for (const auto& test : testCases) {
        auto hashValue = sm3.calculateHash(test.inputText);
        std::string hexHash = convertToHex(hashValue);

        std::cout << "输入: \"" << test.inputText << "\"\n";
        std::cout << "计算结果: " << hexHash << "\n";
        std::cout << "预期结果: " << test.expectedHash << "\n";
        std::cout << "匹配: " << (hexHash == test.expectedHash) << "\n\n";
    }

    return 0;
}
    