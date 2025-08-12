import secrets
from gmssl import sm3, func

class SM2Signature:
    # SM2椭圆曲线参数（国密标准）
    CURVE_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    CURVE_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    CURVE_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    CURVE_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    BASE_X = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    BASE_Y = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    BASE_POINT = (BASE_X, BASE_Y)  # 曲线基点

    @staticmethod
    def modular_inverse(a, p):
        """
        扩展欧几里得算法计算模逆元
        :param a: 待求逆的数
        :param p: 模数
        :return: a关于p的逆元
        """
        if a == 0:
            return 0
        lm, hm = 1, 0
        low, high = a % p, p
        while low > 1:
            r = high // low
            nm, new = hm - lm * r, high - low * r
            lm, low, hm, high = nm, new, lm, low
        return lm % p

    @staticmethod
    def jacobian_double(x1, y1, z1):
        """
        Jacobian坐标下的点加倍运算
        :param x1: 点的X坐标
        :param y1: 点的Y坐标
        :param z1: 点的Z坐标
        :return: 加倍后的点坐标
        """
        if y1 == 0:
            return (0, 0, 0)  # 无穷远点
        
        p, a = SM2Signature.CURVE_P, SM2Signature.CURVE_A
        s = (4 * x1 * y1 * y1) % p
        m = (3 * x1 * x1 + a * z1 **4) % p
        x3 = (m * m - 2 * s) % p
        y3 = (m * (s - x3) - 8 * y1** 4) % p
        z3 = (2 * y1 * z1) % p
        return (x3, y3, z3)

    @staticmethod
    def jacobian_add(x1, y1, z1, x2, y2, z2):
        """
        Jacobian坐标下的点加法运算
        :param x1,y1,z1: 第一个点的坐标
        :param x2,y2,z2: 第二个点的坐标
        :return: 相加后的点坐标
        """
        p = SM2Signature.CURVE_P
        if z1 == 0:
            return (x2, y2, z2)
        if z2 == 0:
            return (x1, y1, z1)
            
        u1 = (x1 * z2 **2) % p
        u2 = (x2 * z1** 2) % p
        s1 = (y1 * z2 **3) % p
        s2 = (y2 * z1** 3) % p
        
        if u1 == u2:
            if s1 != s2:
                return (0, 0, 1)  # 无穷远点
            else:
                return SM2Signature.jacobian_double(x1, y1, z1)
                
        h = (u2 - u1) % p
        r = (s2 - s1) % p
        h_sq = (h * h) % p
        h_cu = (h * h_sq) % p
        u1_h_sq = (u1 * h_sq) % p
        
        x3 = (r * r - h_cu - 2 * u1_h_sq) % p
        y3 = (r * (u1_h_sq - x3) - s1 * h_cu) % p
        z3 = (h * z1 * z2) % p
        return (x3, y3, z3)

    @staticmethod
    def jacobian_to_affine(x, y, z):
        """
        将Jacobian坐标转换为仿射坐标
        :param x,y,z: Jacobian坐标
        :return: 仿射坐标(x, y)
        """
        p = SM2Signature.CURVE_P
        if z == 0:
            return (0, 0)
            
        z_inv = SM2Signature.modular_inverse(z, p)
        z_inv_sq = (z_inv * z_inv) % p
        z_inv_cu = (z_inv_sq * z_inv) % p
        
        x_affine = (x * z_inv_sq) % p
        y_affine = (y * z_inv_cu) % p
        return (x_affine, y_affine)

    @staticmethod
    def point_multiply(k, point):
        """
        椭圆曲线点乘法（使用Jacobian坐标加速）
        :param k: 乘数
        :param point: 椭圆曲线上的点
        :return: 点乘结果
        """
        x1, y1 = point
        x, y, z = 0, 0, 0  # 初始化为无穷远点
        x2, y2, z2 = x1, y1, 1
        
        while k > 0:
            if k & 1:
                if z == 0:
                    x, y, z = x2, y2, z2
                else:
                    x, y, z = SM2Signature.jacobian_add(x, y, z, x2, y2, z2)
            x2, y2, z2 = SM2Signature.jacobian_double(x2, y2, z2)
            k >>= 1
            
        return SM2Signature.jacobian_to_affine(x, y, z)

    @staticmethod
    def _compute_message_hash(message: bytes) -> int:
        """
        计算消息的SM3哈希值
        :param message: 待哈希的消息
        :return: 哈希值（整数形式）
        """
        hash_bytes = sm3.sm3_hash(func.bytes_to_list(message))
        return int(hash_bytes, 16) % SM2Signature.CURVE_N

    def __init__(self):
        self.private_key = None  # 私钥
        self.public_key = None   # 公钥

    def create_key_pair(self):
        """
        生成SM2密钥对
        :return: 私钥和公钥
        """
        self.private_key = secrets.randbelow(SM2Signature.CURVE_N - 1) + 1
        self.public_key = SM2Signature.point_multiply(self.private_key, SM2Signature.BASE_POINT)
        return self.private_key, self.public_key

    def sign_message(self, message: bytes):
        """
        对消息进行签名
        :param message: 待签名的消息
        :return: 签名(r, s)
        """
        if self.private_key is None:
            raise ValueError("私钥未设置")

        e = self._compute_message_hash(message)
        if e == 0:
            e = 1

        # 预计算(1 + dA)^-1 mod N，提高效率
        inv_1_d = SM2Signature.modular_inverse(1 + self.private_key, SM2Signature.CURVE_N)

        while True:
            k = secrets.randbelow(SM2Signature.CURVE_N - 1) + 1
            x1, y1 = SM2Signature.point_multiply(k, SM2Signature.BASE_POINT)
            r = (e + x1) % SM2Signature.CURVE_N
            
            if r == 0 or r + k == SM2Signature.CURVE_N:
                continue
                
            s = (inv_1_d * (k - r * self.private_key)) % SM2Signature.CURVE_N
            if s == 0:
                continue
                
            return (r, s)

    def verify_signature(self, message: bytes, signature):
        """
        验证签名有效性
        :param message: 原始消息
        :param signature: 签名(r, s)
        :return: 验证结果（布尔值）
        """
        if self.public_key is None:
            raise ValueError("公钥未设置")

        r, s = signature
        # 检查r和s的取值范围
        if not (1 <= r < SM2Signature.CURVE_N and 1 <= s < SM2Signature.CURVE_N):
            return False

        e = self._compute_message_hash(message)
        if e == 0:
            e = 1

        t = (r + s) % SM2Signature.CURVE_N
        if t == 0:
            return False

        # 计算sG + tP
        s_g = SM2Signature.point_multiply(s, SM2Signature.BASE_POINT)
        t_p = SM2Signature.point_multiply(t, self.public_key)
        x1, y1 = SM2Signature.point_add(s_g, t_p)
        
        # 验证签名
        R = (e + x1) % SM2Signature.CURVE_N
        return R == r

    @staticmethod
    def point_add(p1, p2):
        """
        仿射坐标下的点加法
        :param p1: 第一个点
        :param p2: 第二个点
        :return: 相加结果
        """
        p = SM2Signature.CURVE_P
        if p1 == (0, 0):
            return p2
        if p2 == (0, 0):
            return p1
        if p1[0] == p2[0] and p1[1] != p2[1]:
            return (0, 0)
            
        # 计算斜率
        if p1 == p2:
            lam = (3 * p1[0] **2 + SM2Signature.CURVE_A) * SM2Signature.modular_inverse(2 * p1[1], p) % p
        else:
            lam = (p2[1] - p1[1]) * SM2Signature.modular_inverse(p2[0] - p1[0], p) % p
            
        x3 = (lam** 2 - p1[0] - p2[0]) % p
        y3 = (lam * (p1[0] - x3) - p1[1]) % p
        return (x3, y3)


if __name__ == "__main__":
    sm2 = SM2Signature()

    # 1. 生成密钥对
    private_key, public_key = sm2.create_key_pair()
    print("私钥:", hex(private_key))
    print("公钥(x,y):", hex(public_key[0]), hex(public_key[1]))

    # 2. 对消息进行签名
    message = b"Hello SM2 Digital Signature"
    signature = sm2.sign_message(message)
    print("签名(r,s):", hex(signature[0]), hex(signature[1]))

    # 3. 验证签名
    is_valid = sm2.verify_signature(message, signature)
    print("签名验证结果:", "有效" if is_valid else "无效")

    # 4. 测试消息篡改检测
    tampered_message = b"Hello SM2 Digital Signature!"
    is_valid_tampered = sm2.verify_signature(tampered_message, signature)
    print("篡改消息验证结果:", "有效" if is_valid_tampered else "无效")

    # 5. 性能测试（100次签名平均耗时）
    import time
    start_time = time.time()
    for _ in range(100):
        sm2.sign_message(message)
    avg_time = (time.time() - start_time) / 100
    print(f"100次签名平均耗时: {avg_time:.4f}秒")
    