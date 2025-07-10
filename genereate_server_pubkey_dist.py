from Crypto.PublicKey import RSA
from crypto_gm import gm_hash
import hashlib

choice = input()

if choice == "gm":
    with open("server_public.pem", "rb") as f:
        cert_data = f.read()

    sm3_digest = gm_hash(cert_data).hex()
    print(f"服务器证书SM3摘要: {sm3_digest }")

    with open("sm3_server_pubkey_dist.txt", "w") as f:
        f.write(sm3_digest )
else:
    with open("server_public.pem", "rb") as f:
        public_key_bytes = f.read()

    # 计算 SHA-256 摘要
    sha256_digest = hashlib.sha256(public_key_bytes).hexdigest()

    print("🔐 服务器公钥摘要 (SHA-256):", sha256_digest)

    with open("sha256_server_pubkey_dist.txt", "w") as f:
        f.write(sha256_digest)