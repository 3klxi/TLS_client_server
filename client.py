import socket
import hashlib
import sys
import os
from common import Message, MessageType, ErrorType, ErrorMessage, ApplicationData
from client_messages import ClientHello, ClientCertificate, CertificateVerify, ClientKeyExchange, ClientFinished
from server_messages import ServerHello, ServerCertificate, ServerFinished
from crypto import *

trusted_pubkey_sha256 = "388d3b9218d10e0936295d347b062a514aa89c2481f01d537c6c75662b376fbb"

class TLSClient:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.socket = None
        
        # # 生成RSA密钥对
        # self.rsa_key = generate_rsa_key()
        # self.private_key = self.rsa_key.export_key(format='PEM')
        # self.public_key = self.rsa_key.publickey().export_key(format='PEM')

        with open("client_private.pem", "rb") as f:
            self.private_key = f.read()
        
        with open("client_public.pem", "rb") as f:
            self.public_key = f.read()
        
        self.rsa_key = RSA.import_key(self.private_key)

        # 握手状态
        self.handshake_complete = False
        
        # 握手消息
        self.client_hello = None
        self.server_hello = None
        self.server_certificate = None
        self.client_certificate = None
        self.certificate_verify = None
        self.client_key_exchange = None
        
        # 密钥材料
        self.master_secret = None
        self.session_key = None
    
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"[*] 成功连接到服务器 {self.host}:{self.port}")
            
            # 执行握手
            if self.perform_handshake():
                # 握手成功，发送应用数据
                self.send_application_data()
            
            self.socket.close()
        
        except Exception as e:
            print(f"[!] 错误: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def perform_handshake(self):
        try:
            # 1. 发送 ClientHello
            self.client_hello = ClientHello()
            self.client_hello_raw = self.client_hello.pack()
            self.send_message(self.client_hello_raw)
            print(f"[*] 发送 ClientHello")
            print(f"    - 随机数: {self.client_hello.random.hex()}")
            print(f"    - 密码套件: {hex(self.client_hello.cipher_suite[0])}")

            # 2. 接收 ServerHello
            data = self.receive_message()
            if not data:
                return False

            self.server_hello_raw = data[:3 + data[2]]  # 保留原始字节
            msg, remaining = Message.unpack(data)
            if msg.msg_type != MessageType.SERVER_HELLO:
                print(f"[!] 预期 ServerHello，但收到 {msg.msg_type}")
                return False

            self.server_hello = ServerHello.from_message(msg)
            print("[*] 收到 ServerHello")
            print(f"    - 随机数: {self.server_hello.random.hex()}")
            print(f"    - 密码套件: {hex(self.server_hello.cipher_suite[0])}")

            # 3. 接收 ServerCertificate
            if remaining:
                msg, _ = Message.unpack(remaining)
                self.server_certificate_raw = remaining[:3 + msg.length] 
            else:
                data = self.receive_message()
                if not data:
                    return False
                msg, _ = Message.unpack(data)
                self.server_certificate_raw = data[:3 + msg.length]  # <- 正确提取长度

            self.server_certificate = ServerCertificate.from_message(msg)

            if msg.msg_type != MessageType.SERVER_CERTIFICATE:
                print(f"[!] 预期 ServerCertificate，但收到 {msg.msg_type}")
                return False

            self.server_certificate = ServerCertificate.from_message(msg)
            print("[*] 收到 ServerCertificate")
            print(f"    - 接受到的服务端的证书长度: {len(self.server_certificate.certificate)} 字节")

            # 验证服务端证书是否可信
            received_cert = self.server_certificate.certificate
            received_sha256 = hashlib.sha256(received_cert).hexdigest()
            if received_sha256 != trusted_pubkey_sha256:
                print("[!] ❌ 服务器公钥摘要不匹配，可能存在中间人攻击！")
                return False
            else:
                print("[*] ✅ 服务器公钥已验证为可信")

            # 4. 生成主密钥
            self.master_secret = os.urandom(48)
            print("[*] 生成主密钥 (master_secret)")
            print(f"    - master_secret: {self.master_secret.hex()}")

            # 5. 使用服务器公钥加密主密钥
            encrypted_secret = rsa_encrypt(self.server_certificate.certificate, self.master_secret)
            self.client_key_exchange = ClientKeyExchange(encrypted_secret)
            print("[*] 使用服务器公钥加密主密钥")
            print(f"    - 加密后长度: {len(encrypted_secret)}")
            print(f"    - 前几个字节: {encrypted_secret[:8].hex()}...")

            # 6. 发送 ClientCertificate
            self.client_certificate = ClientCertificate(self.public_key)
            self.client_certificate_raw = self.client_certificate.pack()
            self.send_message(self.client_certificate_raw)
            print("[*] 发送 ClientCertificate")
            print(f"    - 发送的客户端的证书长度: {len(self.client_certificate.certificate)} 字节")
            
            print(f"{self.client_hello_raw}")
            print(f"{self.server_hello_raw}")
            print(f"{self.server_certificate_raw}")
            
            # 7. 发送 CertificateVerify
            verification_data = (
                self.client_hello_raw +
                self.server_hello_raw +
                self.server_certificate_raw
            )
            verify_hash = hashlib.sha1(verification_data).hexdigest()
            print("[*] 构造 CertificateVerify 签名数据")
            print(f"    - 签名输入数据 SHA1: {verify_hash}")

            signature = rsa_sign(self.private_key, verification_data)
            self.certificate_verify = CertificateVerify(signature)
            self.certificate_verify_raw = self.certificate_verify.pack()
            self.send_message(self.certificate_verify_raw)
            print("[*] 发送 CertificateVerify")
            print(f"    - 签名长度: {len(signature)}")
            print(f"    - 签名前几个字节: {signature[:8].hex()}...")

            # 8. 发送 ClientKeyExchange
            self.send_message(self.client_key_exchange.pack())
            print("[*] 发送 ClientKeyExchange")

            # 9. 派生会话密钥
            self.session_key = derive_key(
                self.master_secret,
                b'KEY',
                self.client_hello.random,
                self.server_hello.random
            )
            print("[*] 派生会话密钥")
            print(f"    - 会话密钥: {self.session_key.hex()}")

            # 10. 接收 ServerFinished
            data = self.receive_message()
            if not data:
                return False
            msg, _ = Message.unpack(data)
            if msg.msg_type != MessageType.SERVER_FINISHED:
                print(f"[!] 预期 ServerFinished，但收到 {msg.msg_type}")
                return False

            server_finished = ServerFinished.from_message(msg)
            print("[*] 收到 ServerFinished")
            print(f"    - MAC: {server_finished.message_mac.hex()}")
            
            print(f"{self.client_hello_raw}")
            print(f"{self.server_hello_raw}")
            print(f"{hashlib.sha256(self.server_certificate_raw).digest()}")
            print(f"{hashlib.sha256(self.client_certificate_raw).digest()}")
            print(f"{self.certificate_verify_raw}")
            print(f"{self.client_key_exchange.pack()}")

            # 11. 验证 ServerFinished
            handshake_messages = (
                self.client_hello_raw +
                self.server_hello_raw +
                hashlib.sha256(self.server_certificate_raw).digest() +
                hashlib.sha256(self.client_certificate_raw).digest() +
                self.certificate_verify_raw +
                self.client_key_exchange.pack()
            )
            handshake_digest = hashlib.sha256(handshake_messages).digest()
            expected_mac = hmac(self.master_secret, b'SERVER' + handshake_digest)
            print("[*] 验证 ServerFinished")
            print(f"    - 握手消息摘要: {handshake_digest.hex()}")
            print(f"    - 期望 MAC: {expected_mac.hex()}")

            if server_finished.message_mac != expected_mac:
                print("[!] 服务器握手验证失败")
                error_msg = ErrorMessage(ErrorType.SERVER_HANDSHAKE_ERROR)
                self.send_message(error_msg.pack())
                return False

            print("[*] 服务器握手验证成功")

            # 12. 发送 ClientFinished
            message_mac = hmac(self.master_secret, b'CLIENT' + handshake_digest)
            client_finished = ClientFinished(message_mac)
            self.send_message(client_finished.pack())
            print("[*] 发送 ClientFinished")
            print(f"    - MAC: {message_mac.hex()}")

            print("[*] 握手完成，建立安全通道")
            self.handshake_complete = True
            return True

        except Exception as e:
            print(f"[!] 握手过程中出错: {e}")
            return False

    
    def send_application_data(self):
        try:
            while self.handshake_complete:
                # 获取用户输入
                message = input("请输入要发送的消息 (输入'exit'退出): ")
                if message.lower() == 'exit':
                    break
                
                # 准备应用数据
                message_bytes = message.encode('utf-8')
                message_length = len(message_bytes).to_bytes(2, byteorder='big')
                data = message_length + message_bytes
                
                # 加密数据
                encrypted_data = aes_encrypt(self.session_key, data)
                app_data = ApplicationData(encrypted_data)
                
                # 发送加密数据
                self.send_message(app_data.pack())
                print("[*] 发送加密应用数据")
                
                # 接收响应
                response_data = self.receive_message()
                if not response_data:
                    break
                
                msg, _ = Message.unpack(response_data)
                if msg.msg_type != MessageType.APPLICATION_DATA:
                    print(f"[!] 预期ApplicationData，但收到 {msg.msg_type}")
                    break
                
                app_response = ApplicationData.from_message(msg)
                
                # 解密响应
                decrypted_response = aes_decrypt(self.session_key, app_response.encrypted_data)
                
                # 提取长度和实际数据
                if len(decrypted_response) >= 2:
                    length = int.from_bytes(decrypted_response[:2], byteorder='big')
                    if len(decrypted_response) >= 2 + length:
                        actual_response = decrypted_response[2:2+length]
                        print(f"[*] 收到服务器响应: {actual_response.decode('utf-8', errors='ignore')}")
                    else:
                        print("[!] 响应数据格式错误")
                else:
                    print("[!] 响应数据太短")
        
        except Exception as e:
            print(f"[!] 发送应用数据时出错: {e}")
    
    def send_message(self, data):
        try:
            self.socket.sendall(data)
            return True
        except Exception as e:
            print(f"[!] 发送消息时出错: {e}")
            return False
    
    def receive_message(self, buffer_size=4096):
        try:
            data = self.socket.recv(buffer_size)
            if not data:
                print("[!] 连接已关闭")
            return data
        except Exception as e:
            print(f"[!] 接收消息时出错: {e}")
            return None

if __name__ == "__main__":
    host = '127.0.0.1'
    port = 8443
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    client = TLSClient(host, port)
    client.connect()