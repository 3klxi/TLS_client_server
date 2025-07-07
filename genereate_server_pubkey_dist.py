from Crypto.PublicKey import RSA
import hashlib

# 读取公钥 PEM 文件内容
with open("server_public.pem", "rb") as f:
    public_key_bytes = f.read()

# 计算 SHA-256 摘要
sha256_digest = hashlib.sha256(public_key_bytes).hexdigest()

print("🔐 服务器公钥摘要 (SHA-256):", sha256_digest)

with open("sha256_server_pubkey_dist.txt", "w") as f:
    f.write(sha256_digest)