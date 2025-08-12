import random
import hashlib
import base64
from gmssl import sm3, func

class SM2Crypto:
    """
    纯Python实现的SM2椭圆曲线密码算法
    支持密钥对生成、数字签名与验证功能
    """
    
    # 国密标准SM2推荐椭圆曲线参数 (GB/T 32918.5-2016)
    CURVE_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    CURVE_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    CURVE_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    CURVE_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    BASE_X = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    BASE_Y = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    BASE_POINT = (BASE_X, BASE_Y)  # 椭圆曲线基点G
    
    @staticmethod
    def modular_inverse(a, p):
        """
        扩展欧几里得算法求模逆元
        :param a: 待求逆的整数
        :param p: 模数
        :return: a模p的逆元
        """
        old_r, r = a, p
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        return old_s % p

    @staticmethod
    def _calculate_hash(message: bytes) -> int:
        """
        采用SM3密码杂凑算法计算消息哈希值
        :param message: 待哈希的消息（字节类型）
        :return: 哈希值的整数表示
        """
        hash_hex = sm3.sm3_hash(func.bytes_to_list(message))  # 获取十六进制哈希串
        return int(hash_hex, 16) % SM2Crypto.CURVE_N

    @staticmethod
    def point_addition(p1, p2, modulus):
        """
        椭圆曲线上的点加法运算
        :param p1: 第一个点坐标(x1, y1)
        :param p2: 第二个点坐标(x2, y2)
        :param modulus: 模数p
        :return: 相加结果点(x3, y3)
        """
        if p1 == (0, 0):
            return p2
        if p2 == (0, 0):
            return p1
        if p1[0] == p2[0] and p1[1] != p2[1]:
            return (0, 0)  # 无穷远点
            
        # 计算斜率λ
        if p1 == p2:
            # 点加倍运算
            numerator = (3 * p1[0] **2 + SM2Crypto.CURVE_A) % modulus
            denominator = (2 * p1[1]) % modulus
        else:
            # 点加法运算
            numerator = (p2[1] - p1[1]) % modulus
            denominator = (p2[0] - p1[0]) % modulus
            
        lam = (numerator * SM2Crypto.modular_inverse(denominator, modulus)) % modulus
        
        # 计算结果点坐标
        x3 = (lam** 2 - p1[0] - p2[0]) % modulus
        y3 = (lam * (p1[0] - x3) - p1[1]) % modulus
        return (x3, y3)
    
    @staticmethod
    def point_multiplication(k, point, modulus):
        """
        椭圆曲线上的点乘法运算（快速幂算法实现）
        :param k: 标量乘数
        :param point: 椭圆曲线上的点(x, y)
        :param modulus: 模数p
        :return: 点乘结果[k]P
        """
        result = (0, 0)  # 初始化为无穷远点
        current = point
        while k > 0:
            if k & 1:
                result = SM2Crypto.point_addition(result, current, modulus)
            current = SM2Crypto.point_addition(current, current, modulus)
            k >>= 1
        return result
    
    def __init__(self):
        self.private_key = None  # 私钥d
        self.public_key = None   # 公钥P = [d]G
    
    def create_key_pair(self):
        """
        生成SM2密钥对
        :return: 私钥和公钥的元组 (private_key, public_key)
        """
        # 生成1到n-1之间的随机私钥
        self.private_key = random.randint(1, SM2Crypto.CURVE_N - 1)
        # 计算公钥: P = [d]G
        self.public_key = SM2Crypto.point_multiplication(
            self.private_key, SM2Crypto.BASE_POINT, SM2Crypto.CURVE_P
        )
        return self.private_key, self.public_key
    
    def generate_signature(self, message):
        """
        对消息进行SM2数字签名
        :param message: 待签名消息（字节类型）
        :return: 签名结果 (r, s)
        """
        if not self.private_key:
            raise ValueError("私钥尚未初始化，请先生成密钥对")
        
        # 计算消息哈希值e
        e = self._calculate_hash(message)
        if e == 0:
            e = 1
            
        while True:
            # 生成随机数k ∈ [1, n-1]
            k = random.randint(1, SM2Crypto.CURVE_N - 1)
            
            # 计算点(x1, y1) = [k]G
            x1, y1 = SM2Crypto.point_multiplication(k, SM2Crypto.BASE_POINT, SM2Crypto.CURVE_P)
            
            # 计算r = (e + x1) mod n
            r = (e + x1) % SM2Crypto.CURVE_N
            if r == 0 or (r + k) % SM2Crypto.CURVE_N == 0:
                continue
                
            # 计算s = ((1 + d)^-1 * (k - r*d)) mod n
            s_numerator = (k - r * self.private_key) % SM2Crypto.CURVE_N
            s_denominator = SM2Crypto.modular_inverse(1 + self.private_key, SM2Crypto.CURVE_N)
            s = (s_numerator * s_denominator) % SM2Crypto.CURVE_N
            
            if s != 0:
                return (r, s)
    
    def validate_signature(self, message, signature):
        """
        验证SM2数字签名的有效性
        :param message: 原始消息（字节类型）
        :param signature: 待验证的签名 (r, s)
        :return: 验证结果（布尔值）
        """
        if not self.public_key:
            raise ValueError("公钥尚未初始化，请先生成密钥对")
            
        r, s = signature
        # 检查r和s的取值范围
        if not (1 <= r < SM2Crypto.CURVE_N and 1 <= s < SM2Crypto.CURVE_N):
            return False
            
        # 计算消息哈希值e
        e = self._calculate_hash(message)
        if e == 0:
            e = 1
            
        # 计算t = (r + s) mod n
        t = (r + s) % SM2Crypto.CURVE_N
        if t == 0:
            return False
            
        # 计算点(x1, y1) = [s]G + [t]P
        s_g = SM2Crypto.point_multiplication(s, SM2Crypto.BASE_POINT, SM2Crypto.CURVE_P)
        t_p = SM2Crypto.point_multiplication(t, self.public_key, SM2Crypto.CURVE_P)
        x1, _ = SM2Crypto.point_addition(s_g, t_p, SM2Crypto.CURVE_P)
        
        # 验证 (e + x1) mod n == r
        return (e + x1) % SM2Crypto.CURVE_N == r


# 算法测试示例
if __name__ == "__main__":
    sm2 = SM2Crypto()
    
    # 1. 生成密钥对
    private_key, public_key = sm2.create_key_pair()
    print("私钥:", hex(private_key))
    print("公钥(x,y):", hex(public_key[0]), hex(public_key[1]))
    
    # 2. 对消息进行签名
    message = b"Hello SM2 Digital Signature"
    signature = sm2.generate_signature(message)
    print("签名(r,s):", hex(signature[0]), hex(signature[1]))
    
    # 3. 验证签名有效性
    is_valid = sm2.validate_signature(message, signature)
    print("签名验证结果:", "有效" if is_valid else "无效")
    
    # 4. 测试消息篡改检测
    tampered_message = b"Hello SM2 Digital Signature!"
    is_valid_tampered = sm2.validate_signature(tampered_message, signature)
    print("篡改消息验证结果:", "有效" if is_valid_tampered else "无效")
    
    # 5. 性能测试（计算100次签名的平均耗时）
    import time
    start_time = time.time()
    for _ in range(100):
        sm2.generate_signature(message)
    avg_time = (time.time() - start_time) / 10
    print(f"100次签名平均耗时: {avg_time:.4f}秒")
    