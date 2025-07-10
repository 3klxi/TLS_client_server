import socket
import hashlib
import sys
import argparse
from dotenv import load_dotenv
from common import Message, MessageType, ErrorType, ErrorMessage, ApplicationData
from client_messages import ClientHello, ClientCertificate, CertificateVerify, ClientKeyExchange, ClientFinished
from server_messages import ServerHello, ServerCertificate, ServerFinished

# 加载环境变量
load_dotenv()

class TLSServer:
    def __init__(self, host=None, port=None, use_gm=False):
        self.host = host or os.getenv('SERVER_HOST', 'localhost')
        self.port = port or int(os.getenv('SERVER_PORT', '8443'))
        self.socket = None
        self.client_socket = None
        self.client_address = None
        self.use_gm = use_gm
        
        # 根据使用的加密算法选择不同的导入模块
        if self.use_gm:
            print("[*] 服务器使用国密算法套件")
            from crypto_gm import (
                generate_rsa_key, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
                aes_encrypt, aes_decrypt, hmac, derive_key, gm_hash
            )
            self.crypto_module = {
                'generate_rsa_key': generate_rsa_key,
                'rsa_encrypt': rsa_encrypt,
                'rsa_decrypt': rsa_decrypt,
                'rsa_sign': rsa_sign,
                'rsa_verify': rsa_verify,
                'aes_encrypt': aes_encrypt,
                'aes_decrypt': aes_decrypt,
                'hmac': hmac,
                'derive_key': derive_key,
                'hash_func': gm_hash
            }
        else:
            print("[*] 服务器使用传统加密算法套件")
            from crypto import (
                generate_rsa_key, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
                aes_encrypt, aes_decrypt, hmac, derive_key
            )
            self.crypto_module = {
                'generate_rsa_key': generate_rsa_key,
                'rsa_encrypt': rsa_encrypt,
                'rsa_decrypt': rsa_decrypt,
                'rsa_sign': rsa_sign,
                'rsa_verify': rsa_verify,
                'aes_encrypt': aes_encrypt,
                'aes_decrypt': aes_decrypt,
                'hmac': hmac,
                'derive_key': derive_key,
                'hash_func': hashlib.sha1 if not use_gm else gm_hash
            }

        # 加载密钥对
        self._load_keys()
        
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
    
    def _load_keys(self):
        """加载服务器密钥对"""
        try:
            with open("server_private.pem", "rb") as f:
                self.private_key = f.read()
            
            with open("server_public.pem", "rb") as f:
                self.public_key = f.read()

            if not self.use_gm:
                # 传统算法需要导入RSA模块
                from Crypto.PublicKey import RSA
                self.rsa_key = RSA.import_key(self.private_key)
            else:
                # 国密算法直接使用原始密钥数据
                self.rsa_key = None
                
        except Exception as e:
            print(f"[!] 加载密钥文件失败: {e}")
            raise
    
    def _get_hash_digest(self, data):
        """根据算法类型获取哈希摘要"""
        if self.use_gm:
            return self.crypto_module['hash_func'](data)
        else:
            return hashlib.sha1(data).digest()
    
    def _get_hash_hex(self, data):
        """根据算法类型获取哈希摘要的十六进制表示"""
        if self.use_gm:
            return self.crypto_module['hash_func'](data).hex()
        else:
            return hashlib.sha1(data).hexdigest()
    
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            crypto_type = "国密" if self.use_gm else "传统"
            print(f"[*] 服务器启动，监听 {self.host}:{self.port} ({crypto_type}算法)")
            
            while True:
                self.client_socket, self.client_address = self.socket.accept()
                print(f"[*] 接受来自 {self.client_address[0]}:{self.client_address[1]} 的连接")
                
                # 处理握手
                if self.handle_handshake():
                    # 握手成功，处理应用数据
                    self.handle_application_data()
                
                self.client_socket.close()
                self.reset_state()
        
        except Exception as e:
            print(f"[!] 错误: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def reset_state(self):
        # 重置握手状态
        self.handshake_complete = False
        self.client_hello = None
        self.server_hello = None
        self.server_certificate = None
        self.client_certificate = None
        self.certificate_verify = None
        self.client_key_exchange = None
        self.master_secret = None
        self.session_key = None
    
    def handle_handshake(self):
        try:
            # 1. 接收 ClientHello
            data = self.receive_message()
            if not data:
                return False

            client_hello_raw = data  # 保留原始数据
            msg, _ = Message.unpack(data)
            if msg.msg_type != MessageType.CLIENT_HELLO:
                print(f"[!] 预期 ClientHello，但收到 {msg.msg_type}")
                return False

            self.client_hello = ClientHello.from_message(msg)
            print("[*] 收到 ClientHello")
            print(f"    - 随机数: {self.client_hello.random.hex()}")
            print(f"    - 密码套件: {hex(self.client_hello.cipher_suite[0])}")

            # 2. 发送 ServerHello
            self.server_hello = ServerHello()
            server_hello_raw = self.server_hello.pack()  # 保留原始数据
            self.send_message(server_hello_raw)
            print("[*] 发送 ServerHello")
            print(f"    - 随机数: {self.server_hello.random.hex()}")
            print(f"    - 密码套件: {hex(self.server_hello.cipher_suite[0])}")

            # 3. 发送 ServerCertificate
            self.server_certificate = ServerCertificate(self.public_key)
            server_cert_raw = self.server_certificate.pack()  # 保留原始数据
            self.send_message(server_cert_raw)
            print("[*] 发送 ServerCertificate")
            print(f"    - 发送的服务端证书长度: {len(self.server_certificate.certificate)} 字节")

            # 4. 接收 ClientCertificate
            data = self.receive_message()
            if not data:
                return False

            msg, remaining = Message.unpack(data)
            if msg.msg_type != MessageType.CLIENT_CERTIFICATE:
                print(f"[!] 预期 ClientCertificate，但收到 {msg.msg_type}")
                return False

            # 正确保存ClientCertificate的原始数据
            client_cert_length = 3 + int.from_bytes(data[1:3], byteorder='big')
            client_cert_raw = data[:client_cert_length]
            
            self.client_certificate = ClientCertificate.from_message(msg)
            print("[*] 收到 ClientCertificate")
            print(f"    - 接受到的客户端的证书长度: {len(self.client_certificate.certificate)} 字节")

            # 5. 接收 CertificateVerify
            if remaining:
                msg, remaining = Message.unpack(remaining)
                # 从原始数据中提取CertificateVerify
                cert_verify_start = client_cert_length
                cert_verify_length = 3 + int.from_bytes(data[cert_verify_start+1:cert_verify_start+3], byteorder='big')
                cert_verify_raw = data[cert_verify_start:cert_verify_start+cert_verify_length]
            else:
                data = self.receive_message()
                if not data:
                    return False
                msg, remaining = Message.unpack(data)
                cert_verify_raw = data  # 如果是单独的消息，整个data就是原始数据

            if msg.msg_type != MessageType.CERTIFICATE_VERIFY:
                print(f"[!] 预期 CertificateVerify，但收到 {msg.msg_type}")
                return False
    
            self.certificate_verify = CertificateVerify.from_message(msg)
            print("[*] 收到 CertificateVerify")
            print(f"    - 签名长度: {len(self.certificate_verify.signature)} 字节")
            print(f"    - 签名前几个字节: {self.certificate_verify.signature[:8].hex()}...")

            # 用原始数据拼接签名数据进行验证
            verification_data = client_hello_raw + server_hello_raw + server_cert_raw
            verify_hash = self._get_hash_hex(verification_data)
            hash_type = "SM3" if self.use_gm else "SHA1"
            print(f"    - 签名验证数据 {hash_type}: {verify_hash}")
            
            if not self.crypto_module['rsa_verify'](
                self.client_certificate.certificate,
                verification_data,
                self.certificate_verify.signature
            ):
                print("[!] 客户端证书验证失败")
                error_msg = ErrorMessage(ErrorType.CLIENT_CERTIFICATE_ERROR)
                self.send_message(error_msg.pack())
                return False

            print("[*] ✅ 客户端证书验证成功")

            # 6. 接收 ClientKeyExchange
            if remaining:
                client_key_exchange_raw = remaining[:3 + remaining[2]]  # 正确保存
                msg, _ = Message.unpack(remaining)
            else:
                data = self.receive_message()
                if not data:
                    return False
                client_key_exchange_raw = data[:3 + data[2]]  # 正确保存
                msg, _ = Message.unpack(data)

            if msg.msg_type != MessageType.CLIENT_KEY_EXCHANGE:
                print(f"[!] 预期 ClientKeyExchange，但收到 {msg.msg_type}")
                return False

            self.client_key_exchange = ClientKeyExchange.from_message(msg)
            print("[*] 收到 ClientKeyExchange")
            print(f"    - 加密主密钥长度: {len(self.client_key_exchange.encrypted_shared_secret)} 字节")
            print(f"    - 加密主密钥前几个字节: {self.client_key_exchange.encrypted_shared_secret[:8].hex()}...")

            # 解密主密钥
            self.master_secret = self.crypto_module['rsa_decrypt'](self.private_key, self.client_key_exchange.encrypted_shared_secret)
            if not self.master_secret or len(self.master_secret) != 48:
                print("[!] 主密钥解密失败")
                return False
            print("[*] 主密钥解密成功")
            print(f"    - master_secret: {self.master_secret.hex()}")

            # 生成会话密钥
            self.session_key = self.crypto_module['derive_key'](
                self.master_secret,
                b'KEY',
                self.client_hello.random,
                self.server_hello.random
            )
            print(f"    - 会话密钥 (session_key): {self.session_key.hex()}")
            
            # 7. 发送 ServerFinished - 使用原始数据构造握手消息
            handshake_messages = (
                client_hello_raw +
                server_hello_raw +
                hashlib.sha256(server_cert_raw).digest() +
                hashlib.sha256(client_cert_raw).digest() +
                cert_verify_raw +
                client_key_exchange_raw
            )
            print(f"    - 握手消息摘要: {hashlib.sha256(handshake_messages).hexdigest()}")
            
            message_mac = self.crypto_module['hmac'](
                self.master_secret,
                b'SERVER' + hashlib.sha256(handshake_messages).digest()
            )
            server_finished = ServerFinished(message_mac)
            self.send_message(server_finished.pack())
            print("[*] 发送 ServerFinished")
            print(f"    - ServerFinished MAC: {message_mac.hex()}")

            # 8. 接收 ClientFinished
            data = self.receive_message()
            if not data:
                return False

            msg, _ = Message.unpack(data)
            if msg.msg_type != MessageType.CLIENT_FINISHED:
                print(f"[!] 预期 ClientFinished，但收到 {msg.msg_type}")
                return False

            client_finished = ClientFinished.from_message(msg)
            print("[*] 收到 ClientFinished")
            print(f"    - ClientFinished MAC: {client_finished.message_mac.hex()}")

            expected_mac = self.crypto_module['hmac'](
                self.master_secret,
                b'CLIENT' + hashlib.sha256(handshake_messages).digest()
            )
            print(f"    - 期望 MAC: {expected_mac.hex()}")

            if client_finished.message_mac != expected_mac:
                print("[!] 客户端握手验证失败")
                error_msg = ErrorMessage(ErrorType.CLIENT_HANDSHAKE_ERROR)
                self.send_message(error_msg.pack())
                return False

            print("[*] 客户端握手验证成功")
            crypto_type = "国密" if self.use_gm else "传统"
            print(f"[*] 握手完成，建立安全通道 ({crypto_type}算法)")

            self.handshake_complete = True
            return True

        except Exception as e:
            print(f"[!] 握手过程中出错: {e}")
            return False
    
    def handle_application_data(self):
        try:
            while self.handshake_complete:
                data = self.receive_message()
                if not data:
                    break
                
                msg, _ = Message.unpack(data)
                if msg.msg_type != MessageType.APPLICATION_DATA:
                    print(f"[!] 预期ApplicationData，但收到 {msg.msg_type}")
                    break
                
                app_data = ApplicationData.from_message(msg)

                # 解密应用数据
                decrypted_data = self.crypto_module['aes_decrypt'](self.session_key, app_data.encrypted_data)
                
                # 提取长度和实际数据
                if len(decrypted_data) >= 2:
                    length = int.from_bytes(decrypted_data[:2], byteorder='big')
                    if len(decrypted_data) >= 2 + length:
                        actual_data = decrypted_data[2:2+length]
                        crypto_type = "国密" if self.use_gm else "传统"
                        print(f"[*] 收到解密后的应用数据 ({crypto_type}算法): {actual_data.decode('utf-8', errors='ignore')}")
                        
                        # 回复消息
                        response = f"服务器收到: {actual_data.decode('utf-8', errors='ignore')}".encode('utf-8')
                        response_length = len(response).to_bytes(2, byteorder='big')
                        response_data = response_length + response
                        
                        # 加密响应
                        encrypted_response = self.crypto_module['aes_encrypt'](self.session_key, response_data)
                        response_msg = ApplicationData(encrypted_response)
                        
                        self.send_message(response_msg.pack())
                        print(f"[*] 发送加密响应 ({crypto_type}算法)")
                    else:
                        print("[!] 应用数据格式错误")
                else:
                    print("[!] 应用数据太短")
        
        except Exception as e:
            print(f"[!] 处理应用数据时出错: {e}")

    def send_message(self, data):
        try:
            self.client_socket.sendall(data)
            return True
        except Exception as e:
            print(f"[!] 发送消息时出错: {e}")
            return False
    
    def receive_message(self, buffer_size=4096):
        try:
            data = self.client_socket.recv(buffer_size)
            if not data:
                print("[!] 连接已关闭")
            return data
        except Exception as e:
            print(f"[!] 接收消息时出错: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='TLS服务器 - 支持国密算法')
    parser.add_argument('--host', default='localhost', help='服务器地址 (默认: localhost)')
    parser.add_argument('--port', type=int, default=8443, help='服务器端口 (默认: 8443)')
    parser.add_argument('--crypto', choices=['standard', 'gm'], default='standard', 
                        help='加密算法类型: standard(传统算法) 或 gm(国密算法) (默认: standard)')
    
    args = parser.parse_args()
    
    # 确定是否使用国密算法
    use_gm = args.crypto == 'gm'
    
    server = TLSServer(args.host, args.port, use_gm)
    server.start()

if __name__ == "__main__":
    main()