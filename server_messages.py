import os
from common import Message, MessageType, CipherSuite

# ServerHello消息
class ServerHello(Message):
    def __init__(self):
        super().__init__(MessageType.SERVER_HELLO)
        self.random = os.urandom(32)  # 生成32字节随机数
        self.cipher_suite = bytes([CipherSuite.create()])  # 选择的密码套件
        
        # 设置消息体和长度
        self.body = self.random + self.cipher_suite
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.SERVER_HELLO or len(message.body) < 33:
            return None
        
        server_hello = ServerHello()
        server_hello.random = message.body[:32]
        server_hello.cipher_suite = message.body[32:33]
        return server_hello

# ServerCertificate消息
class ServerCertificate(Message):
    def __init__(self, certificate=None):
        super().__init__(MessageType.SERVER_CERTIFICATE)
        self.certificate = certificate or b''  # 简化为只存储RSA公钥
        
        # 设置消息体和长度
        self.body = self.certificate
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.SERVER_CERTIFICATE:
            return None
        
        server_cert = ServerCertificate()
        server_cert.certificate = message.body
        return server_cert

# ServerFinished消息
class ServerFinished(Message):
    def __init__(self, message_mac=None):
        super().__init__(MessageType.SERVER_FINISHED)
        self.message_mac = message_mac or b''  # HMAC值
        
        # 设置消息体和长度
        self.body = self.message_mac
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.SERVER_FINISHED:
            return None
        
        server_finished = ServerFinished()
        server_finished.message_mac = message.body
        return server_finished