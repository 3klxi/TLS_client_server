import os
from common import Message, MessageType, CipherSuite

# ClientHello消息
class ClientHello(Message):
    def __init__(self):
        super().__init__(MessageType.CLIENT_HELLO)
        self.random = os.urandom(32)  # 生成32字节随机数
        self.cipher_suite = bytes([CipherSuite.create(), 0])  # 第二个字节保留
        
        # 设置消息体和长度
        self.body = self.random + self.cipher_suite  # 34字节的 BODY
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.CLIENT_HELLO or len(message.body) != 34:
            return None
        
        client_hello = ClientHello()
        client_hello.random = message.body[:32]
        client_hello.cipher_suite = message.body[32:34]
        return client_hello

# ClientCertificate消息
class ClientCertificate(Message):
    def __init__(self, certificate=None):
        super().__init__(MessageType.CLIENT_CERTIFICATE)
        self.certificate = certificate or b''  # 简化为只存储RSA公钥
        
        # 设置消息体和长度
        self.body = self.certificate
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.CLIENT_CERTIFICATE:
            return None
        
        client_cert = ClientCertificate()
        client_cert.certificate = message.body
        return client_cert

# CertificateVerify消息
class CertificateVerify(Message):
    def __init__(self, signature=None):
        super().__init__(MessageType.CERTIFICATE_VERIFY)
        self.signature = signature or b''  # 签名
        
        # 设置消息体和长度
        self.body = self.signature
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.CERTIFICATE_VERIFY:
            return None
        
        cert_verify = CertificateVerify()
        cert_verify.signature = message.body
        return cert_verify

# ClientKeyExchange消息
class ClientKeyExchange(Message):
    def __init__(self, encrypted_shared_secret=None):
        super().__init__(MessageType.CLIENT_KEY_EXCHANGE)
        self.encrypted_shared_secret = encrypted_shared_secret or b''  # 加密的共享密钥
        
        # 设置消息体和长度
        self.body = self.encrypted_shared_secret
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.CLIENT_KEY_EXCHANGE:
            return None
        
        client_key_exchange = ClientKeyExchange()
        client_key_exchange.encrypted_shared_secret = message.body
        return client_key_exchange

# ClientFinished消息
class ClientFinished(Message):
    def __init__(self, message_mac=None):
        super().__init__(MessageType.CLIENT_FINISHED)
        self.message_mac = message_mac or b''  # HMAC值
        
        # 设置消息体和长度
        self.body = self.message_mac
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.CLIENT_FINISHED:
            return None
        
        client_finished = ClientFinished()
        client_finished.message_mac = message.body
        return client_finished