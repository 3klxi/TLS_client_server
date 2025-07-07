from Crypto.PublicKey import RSA

key = RSA.generate(1024)
print("[Private Key]:")
print(key.export_key().decode())

print("\n[Public Key]:")
print(key.publickey().export_key().decode())
