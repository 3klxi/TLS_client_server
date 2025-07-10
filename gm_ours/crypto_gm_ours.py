import os
import logging
import hashlib
import struct
from typing import Tuple, Optional

# 国密算法模块 - 提供SM2、SM3、SM4算法实现
# 作为crypto.py的国密替代版本

# ==================== SM3 哈希算法 ====================
class SM3:
    """SM3密码杂凑算法实现"""
    
    def __init__(self):
        self.digest_size = 32
        self.block_size = 64
        
    @staticmethod
    def _rotl(x, n):
        """循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    @staticmethod
    def _ff(x, y, z, j):
        """布尔函数FF"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)
    
    @staticmethod
    def _gg(x, y, z, j):
        """布尔函数GG"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | (~x & z)
    
    @staticmethod
    def _p0(x):
        """置换函数P0"""
        return x ^ SM3._rotl(x, 9) ^ SM3._rotl(x, 17)
    
    @staticmethod
    def _p1(x):
        """置换函数P1"""
        return x ^ SM3._rotl(x, 15) ^ SM3._rotl(x, 23)
    
    def hash(self, data: bytes) -> bytes:
        """计算SM3哈希值"""
        # 初始值
        iv = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
              0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
        
        # 填充
        msg_len = len(data) * 8
        data += b'\x80'
        while len(data) % 64 != 56:
            data += b'\x00'
        data += struct.pack('>Q', msg_len)
        
        # 处理每个512位分组
        for i in range(0, len(data), 64):
            block = data[i:i+64]
            w = list(struct.unpack('>16I', block))
            
            # 扩展
            for j in range(16, 68):
                w.append(SM3._p1(w[j-16] ^ w[j-9] ^ SM3._rotl(w[j-3], 15)) ^ SM3._rotl(w[j-13], 7) ^ w[j-6])
            
            w1 = []
            for j in range(64):
                w1.append(w[j] ^ w[j+4])
            
            # 压缩
            a, b, c, d, e, f, g, h = iv
            for j in range(64):
                t = 0x79cc4519 if j < 16 else 0x7a879d8a
                ss1 = SM3._rotl((SM3._rotl(a, 12) + e + SM3._rotl(t, j % 32)) & 0xffffffff, 7)
                ss2 = ss1 ^ SM3._rotl(a, 12)
                tt1 = (SM3._ff(a, b, c, j) + d + ss2 + w1[j]) & 0xffffffff
                tt2 = (SM3._gg(e, f, g, j) + h + ss1 + w[j]) & 0xffffffff
                d = c
                c = SM3._rotl(b, 9)
                b = a
                a = tt1
                h = g
                g = SM3._rotl(f, 19)
                f = e
                e = SM3._p0(tt2)
                
                a, b, c, d, e, f, g, h = a & 0xffffffff, b & 0xffffffff, c & 0xffffffff, d & 0xffffffff, e & 0xffffffff, f & 0xffffffff, g & 0xffffffff, h & 0xffffffff
            
            iv = [a ^ iv[0], b ^ iv[1], c ^ iv[2], d ^ iv[3],
                  e ^ iv[4], f ^ iv[5], g ^ iv[6], h ^ iv[7]]
            iv = [x & 0xffffffff for x in iv]
        
        return struct.pack('>8I', *iv)

# ==================== SM4 分组密码算法 ====================
class SM4:
    """SM4分组密码算法实现"""
    
    # S盒
    S_BOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]
    
    # 系统参数FK
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    
    # 固定参数CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]
    
    def __init__(self, key: bytes):
        """初始化SM4密码"""
        if len(key) != 16:
            raise ValueError("SM4密钥长度必须为16字节")
        self.round_keys = self._key_expansion(key)
    
    @staticmethod
    def _rotl(x, n):
        """循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    @classmethod
    def _sbox(cls, x):
        """S盒变换"""
        return cls.S_BOX[x]
    
    @classmethod
    def _tau(cls, x):
        """非线性变换τ"""
        return (cls._sbox((x >> 24) & 0xff) << 24) | \
               (cls._sbox((x >> 16) & 0xff) << 16) | \
               (cls._sbox((x >> 8) & 0xff) << 8) | \
               cls._sbox(x & 0xff)
    
    @classmethod
    def _l(cls, x):
        """线性变换L"""
        return x ^ cls._rotl(x, 2) ^ cls._rotl(x, 10) ^ cls._rotl(x, 18) ^ cls._rotl(x, 24)
    
    @classmethod
    def _l_prime(cls, x):
        """线性变换L'"""
        return x ^ cls._rotl(x, 13) ^ cls._rotl(x, 23)
    
    def _key_expansion(self, key: bytes) -> list:
        """密钥扩展"""
        # 将密钥分为4个32位字
        mk = list(struct.unpack('>4I', key))
        
        # 计算K0, K1, K2, K3
        k = [mk[i] ^ self.FK[i] for i in range(4)]
        
        # 生成32个轮密钥
        round_keys = []
        for i in range(32):
            rk = k[0] ^ self._l_prime(self._tau(k[1] ^ k[2] ^ k[3] ^ self.CK[i]))
            round_keys.append(rk)
            k = k[1:] + [rk]
        
        return round_keys
    
    def _encrypt_block(self, plaintext: bytes) -> bytes:
        """加密单个分组"""
        # 将明文分为4个32位字
        x = list(struct.unpack('>4I', plaintext))
        
        # 32轮迭代
        for i in range(32):
            x[0] = x[0] ^ self._l(self._tau(x[1] ^ x[2] ^ x[3] ^ self.round_keys[i]))
            x = x[1:] + [x[0]]
        
        # 反序变换
        return struct.pack('>4I', x[3], x[2], x[1], x[0])
    
    def _decrypt_block(self, ciphertext: bytes) -> bytes:
        """解密单个分组"""
        # 将密文分为4个32位字
        x = list(struct.unpack('>4I', ciphertext))
        
        # 32轮迭代（使用逆序轮密钥）
        for i in range(32):
            x[0] = x[0] ^ self._l(self._tau(x[1] ^ x[2] ^ x[3] ^ self.round_keys[31-i]))
            x = x[1:] + [x[0]]
        
        # 反序变换
        return struct.pack('>4I', x[3], x[2], x[1], x[0])
    
    def encrypt(self, data: bytes) -> bytes:
        """SM4-ECB加密（带ISO/IEC 7816-4填充）"""
        # ISO/IEC 7816-4填充
        padded_data = data + b'\x80'
        if len(padded_data) % 16 != 0:
            padded_data += b'\x00' * (16 - len(padded_data) % 16)
        
        # 分组加密
        result = b''
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            result += self._encrypt_block(block)
        
        return result
    
    def decrypt(self, data: bytes) -> bytes:
        """SM4-ECB解密（移除ISO/IEC 7816-4填充）"""
        # 分组解密
        result = b''
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            result += self._decrypt_block(block)
        
        # 移除填充
        i = len(result) - 1
        while i >= 0 and result[i] == 0:
            i -= 1
        if i >= 0 and result[i] == 0x80:
            return result[:i]
        return result

# ==================== SM2 椭圆曲线公钥密码算法 ====================
class SM2:
    """SM2椭圆曲线公钥密码算法实现（简化版）"""
    
    # SM2推荐曲线参数
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    
    def __init__(self):
        self.sm3 = SM3()
    
    def _mod_inverse(self, a, m):
        """模逆运算"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError("模逆不存在")
        return (x % m + m) % m
    
    def _point_add(self, p1, p2):
        """椭圆曲线点加运算"""
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        
        x1, y1 = p1
        x2, y2 = p2
        
        if x1 == x2:
            if y1 == y2:
                # 点倍运算
                s = (3 * x1 * x1 + self.A) * self._mod_inverse(2 * y1, self.P) % self.P
            else:
                return None  # 无穷远点
        else:
            s = (y2 - y1) * self._mod_inverse(x2 - x1, self.P) % self.P
        
        x3 = (s * s - x1 - x2) % self.P
        y3 = (s * (x1 - x3) - y1) % self.P
        
        return (x3, y3)
    
    def _point_multiply(self, k, point):
        """椭圆曲线点乘运算"""
        if k == 0:
            return None
        if k == 1:
            return point
        
        result = None
        addend = point
        
        while k:
            if k & 1:
                result = self._point_add(result, addend)
            addend = self._point_add(addend, addend)
            k >>= 1
        
        return result
    
    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对"""
        # 生成私钥（随机数）
        private_key = int.from_bytes(os.urandom(32), 'big') % (self.N - 1) + 1
        
        # 计算公钥
        public_key = self._point_multiply(private_key, (self.GX, self.GY))
        
        logging.info(f"[SM2 Private Key]: {hex(private_key)}")
        logging.info(f"[SM2 Public Key]: ({hex(public_key[0])}, {hex(public_key[1])})")
        
        return private_key, public_key
    
    def sign(self, private_key: int, data: bytes) -> Tuple[int, int]:
        """SM2数字签名"""
        # 计算消息摘要
        digest = self.sm3.hash(data)
        e = int.from_bytes(digest, 'big')
        
        while True:
            # 生成随机数k
            k = int.from_bytes(os.urandom(32), 'big') % (self.N - 1) + 1
            
            # 计算(x1, y1) = k * G
            point = self._point_multiply(k, (self.GX, self.GY))
            x1 = point[0]
            
            # 计算r = (e + x1) mod n
            r = (e + x1) % self.N
            if r == 0 or r + k == self.N:
                continue
            
            # 计算s = (1 + dA)^(-1) * (k - r * dA) mod n
            inv = self._mod_inverse(1 + private_key, self.N)
            s = (inv * (k - r * private_key)) % self.N
            if s == 0:
                continue
            
            return (r, s)
    
    def verify(self, public_key: Tuple[int, int], data: bytes, signature: Tuple[int, int]) -> bool:
        """SM2签名验证"""
        r, s = signature
        
        # 检查签名参数
        if not (1 <= r < self.N and 1 <= s < self.N):
            return False
        
        # 计算消息摘要
        digest = self.sm3.hash(data)
        e = int.from_bytes(digest, 'big')
        
        # 计算t = (r + s) mod n
        t = (r + s) % self.N
        if t == 0:
            return False
        
        # 计算(x1', y1') = s * G + t * PA
        point1 = self._point_multiply(s, (self.GX, self.GY))
        point2 = self._point_multiply(t, public_key)
        point = self._point_add(point1, point2)
        
        if point is None:
            return False
        
        x1_prime = point[0]
        
        # 计算R = (e + x1') mod n
        R = (e + x1_prime) % self.N
        
        return R == r

# ==================== 国密HMAC实现 ====================
def gm_hmac(key: bytes, data: bytes) -> bytes:
    """基于SM3的HMAC实现"""
    sm3 = SM3()
    block_size = 64  # SM3的块大小为64字节
    
    # 如果密钥长度超过块大小，使用SM3处理
    if len(key) > block_size:
        key = sm3.hash(key)
    
    # 如果密钥长度小于块大小，在末尾补0
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))
    
    # 计算K0 XOR ipad和K0 XOR opad
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5c] * block_size)
    
    k_ipad = bytes(x ^ y for x, y in zip(key, ipad))
    k_opad = bytes(x ^ y for x, y in zip(key, opad))
    
    # 计算HMAC
    inner_hash = sm3.hash(k_ipad + data)
    outer_hash = sm3.hash(k_opad + inner_hash)
    
    return outer_hash

# ==================== 国密密钥派生函数 ====================
def gm_derive_key(master_secret: bytes, key_label: bytes, client_random: bytes, server_random: bytes) -> bytes:
    """基于SM3的密钥派生函数"""
    # X = HMAC-SM3(master_secret, key_label||ClientHello.random||ServerHello.random)
    data = key_label + client_random + server_random
    x = gm_hmac(master_secret, data)
    
    # 加密密钥SKey = X1X2...X16
    return x[:16]

# ==================== 统一接口函数 ====================
def generate_gm_key():
    """生成国密密钥对（SM2）"""
    sm2 = SM2()
    return sm2.generate_keypair()

def gm_encrypt(key, data):
    """国密加密（SM4）"""
    sm4 = SM4(key)
    return sm4.encrypt(data)

def gm_decrypt(key, encrypted_data):
    """国密解密（SM4）"""
    sm4 = SM4(key)
    return sm4.decrypt(encrypted_data)

def gm_sign(private_key, data):
    """国密签名（SM2）"""
    sm2 = SM2()
    return sm2.sign(private_key, data)

def gm_verify(public_key, data, signature):
    """国密签名验证（SM2）"""
    sm2 = SM2()
    return sm2.verify(public_key, data, signature)

def gm_hash(data):
    """国密哈希（SM3）"""
    sm3 = SM3()
    return sm3.hash(data)

# ==================== 使用示例 ====================
if __name__ == "__main__":
    # SM3哈希测试
    sm3 = SM3()
    test_data = b"abc"
    hash_result = sm3.hash(test_data)
    print(f"SM3('{test_data.decode()}'): {hash_result.hex()}")
    
    # SM4加密测试
    key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    sm4 = SM4(key)
    plaintext = b"Hello, SM4!"
    ciphertext = sm4.encrypt(plaintext)
    decrypted = sm4.decrypt(ciphertext)
    print(f"SM4加密测试: {plaintext} -> {ciphertext.hex()} -> {decrypted}")
    
    # SM2签名测试
    sm2 = SM2()
    private_key, public_key = sm2.generate_keypair()
    message = b"Hello, SM2!"
    signature = sm2.sign(private_key, message)
    is_valid = sm2.verify(public_key, message, signature)
    print(f"SM2签名验证: {is_valid}")