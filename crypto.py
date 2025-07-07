import os
import logging
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

# RSA密钥生成
def generate_rsa_key(bits=1024):
    key = RSA.generate(bits)
    logging.info(f"[Private Key]:{key.export_key().decode()}")
    logging.info(f"[Public Key]: {key.publickey().export_key().decode()}")
    return key

# RSA加密 (PKCS#1 v1.5)
def rsa_encrypt(public_key, data):
    cipher = PKCS1_v1_5.new(RSA.import_key(public_key))
    return cipher.encrypt(data)

# RSA解密 (PKCS#1 v1.5)
def rsa_decrypt(private_key, encrypted_data):
    cipher = PKCS1_v1_5.new(RSA.import_key(private_key))
    sentinel = None  # 解密失败时返回None
    return cipher.decrypt(encrypted_data, sentinel)


# RSA签名 (PKCS#1 v1.5 with SHA-1)
def rsa_sign(private_key, data):
    key = RSA.import_key(private_key)
    h = SHA1.new(data)
    # 按照PKCS#1 v1.5规范进行签名
    signer = pkcs1_15.new(key)
    signature = signer.sign(h)
    return signature

# RSA签名验证
def rsa_verify(public_key, data, signature):
    key = RSA.import_key(public_key)
    h = SHA1.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ISO/IEC 7816-4 padding
# AES-128-CBC加密
def aes_encrypt(key, data):
    # 初始向量全为0
    iv = b'\x00' * 16
    
    # 填充数据
    # 在明文M后附加0x80，然后在右端填充最少的0x00，使得填充后消息长度为16的整数倍
    padded_data = data + b'\x80'
    if len(padded_data) % 16 != 0:
        padded_data += b'\x00' * (16 - len(padded_data) % 16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded_data)

# AES-128-CBC解密
def aes_decrypt(key, encrypted_data):
    # 初始向量全为0
    iv = b'\x00' * 16
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # 移除填充
    # 从右向左查找第一个0x80，移除它和它右边的所有0x00
    i = len(decrypted_data) - 1
    while i >= 0 and decrypted_data[i] == 0:
        i -= 1
    if i >= 0 and decrypted_data[i] == 0x80:
        return decrypted_data[:i]
    return decrypted_data  # 如果没有找到0x80，返回原始数据

# HMAC-SHA256
def hmac(key, data):
    # 按照FIPS PUB 198-1规范实现HMAC
    block_size = 64  # SHA-256的块大小为64字节
    
    # 如果密钥长度超过块大小，使用哈希函数处理
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    
    # 如果密钥长度小于块大小，在末尾补0
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))
    
    # 计算K0 XOR ipad和K0 XOR opad
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5c] * block_size)
    
    k_ipad = bytes(x ^ y for x, y in zip(key, ipad))
    k_opad = bytes(x ^ y for x, y in zip(key, opad))
    
    # 计算HMAC
    inner_hash = hashlib.sha256(k_ipad + data).digest()
    outer_hash = hashlib.sha256(k_opad + inner_hash).digest()
    
    return outer_hash

# 密钥派生函数
def derive_key(master_secret, key_label, client_random, server_random):
    # 按照实验指导书中的方法计算会话密钥
    # key_label为3字节ASCII码"KEY"
    key_label_bytes = b'KEY'
    
    # X = HMAC(master_secret, key_label||ClientHello.random||ServerHello.random)
    data = key_label_bytes + client_random + server_random
    x = hmac(master_secret, data)
    
    # 加密密钥SKey = X1X2...X16
    return x[:16]