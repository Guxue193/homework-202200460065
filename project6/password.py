import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

class PasswordCheckupClient:
    """
    客户端实现，用于Google密码检查协议
    对应论文中的客户端步骤（Figure 2）
    """
    
    def __init__(self, username, password):
        """
        初始化客户端对象
        :param username: 用户名
        :param password: 密码
        """
        self.username = username
        self.password = password
        
    def generate_credentials(self):
        """
        生成协议所需的凭证
        对应论文中的步骤1
        """
        # 使用HKDF算法派生密钥
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'password-checkup-key',
            backend=default_backend()
        )
        secret_key = hkdf.derive(self.password.encode())  # 从密码派生出密钥
        
        # 计算u值：使用HMAC-SHA256算法，以secret_key为密钥，用户名为消息
        h = hmac.new(secret_key, self.username.encode(), hashlib.sha256)
        u = h.digest()  # 得到u值
        
        # 计算v值：对密码进行SHA256哈希
        v = hashlib.sha256(self.password.encode()).digest()
        
        return u, v  # 返回生成的u和v值

class PasswordCheckupServer:
    """
    服务端实现，用于密码检查协议
    对应论文中的步骤2-4
    """
    
    def __init__(self, leaked_creds_db):
        """
        初始化服务端对象
        :param leaked_creds_db: 已泄露的凭证数据库，格式为(u, v)列表
        """
        self.leaked_db = set(leaked_creds_db)  # 将泄露的凭证存储为集合
        
    def build_bloom_filter(self):
        """
        构建布隆过滤器
        简化实现，实际应用中应使用更高效的数据结构
        """
        # 初始化布隆过滤器
        self.filter = set()
        for u, v in self.leaked_db:
            # 计算h值：H(u) XOR v
            h_u = hashlib.sha256(u).digest()  # 对u进行SHA256哈希
            h_xor = bytes(a ^ b for a, b in zip(h_u, v))  # 计算XOR结果
            self.filter.add(h_xor)  # 将结果添加到布隆过滤器中
    
    def check_password(self, client_u, client_v):
        """
        检查密码是否泄露
        对应论文中的步骤3-4
        """
        # 计算h值：H(client_u) XOR client_v
        h_u = hashlib.sha256(client_u).digest()  # 对client_u进行SHA256哈希
        h_xor = bytes(a ^ b for a, b in zip(h_u, client_v))  # 计算XOR结果
        
        # 检查h值是否在布隆过滤器中
        return h_xor in self.filter

# 使用示例
if __name__ == "__main__":
    # 模拟已泄露的凭证库
    leaked_database = [
        (b'u1_leaked', b'v1_leaked'),  # 实际应为(hash, hash)格式
        (b'u2_leaked', b'v2_leaked')
    ]
    
    # 初始化服务端
    server = PasswordCheckupServer(leaked_database)
    server.build_bloom_filter()  # 构建布隆过滤器
    
    # 客户端检查密码
    client = PasswordCheckupClient("user123", "mypassword")
    u, v = client.generate_credentials()  # 生成客户端凭证
    
    # 检查密码是否泄露
    is_leaked = server.check_password(u, v)
    print(f"密码泄露状态: {'存在泄露风险' if is_leaked else '安全'}")
    
    # 测试已知泄露案例
    test_client = PasswordCheckupClient("leaked_user", "password123")
    test_u, test_v = test_client.generate_credentials()
    server.check_password(test_u, test_v)  # 应返回True