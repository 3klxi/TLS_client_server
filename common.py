import struct
import os
from enum import IntEnum

# 消息类型定义
class MessageType(IntEnum):
    CLIENT_HELLO = 0x80
    SERVER_HELLO = 0x81         
    SERVER_CERTIFICATE = 0x82   # 130
    CLIENT_CERTIFICATE = 0x83
    CERTIFICATE_VERIFY = 0x84
    CLIENT_KEY_EXCHANGE = 0x85
    SERVER_FINISHED = 0x86
    CLIENT_FINISHED = 0x87
    ERROR_MESSAGE = 0x88        # 136
    APPLICATION_DATA = 0x89

# 错误消息类型
class ErrorType(IntEnum):
    CLIENT_CIPHER_SUITE_ERROR = 0x01
    SERVER_CIPHER_SUITE_ERROR = 0x02
    CLIENT_CERTIFICATE_ERROR = 0x03
    SERVER_CERTIFICATE_ERROR = 0x04
    CLIENT_HANDSHAKE_ERROR = 0x05
    SERVER_HANDSHAKE_ERROR = 0x08
    RECORD_ERROR = 0x09

# 密码套件定义
class CipherSuite:
    # 支持RSA算法进行密钥交换
    RSA_KEY_EXCHANGE = 0x01
    # 支持使用AES-128算法进行记录层数据加密
    AES_128_ENCRYPTION = 0x20
    
    @staticmethod
    def create(key_exchange=True, encryption=True):
        value = 0
        if key_exchange:
            value |= CipherSuite.RSA_KEY_EXCHANGE
        if encryption:
            value |= CipherSuite.AES_128_ENCRYPTION
        return value

# 消息基类
class Message:
    def __init__(self, msg_type):
        self.msg_type = msg_type
        self.length = 0
        self.body = b''
    
    # 将消息对象（包含类型、长度、消息体）编码成可以通过网络传输的二进制格式，符合协议格式要求。
    # ！：表示网络字节序（big-endian，大端）
    #B：表示无符号字符（1字节）→ msg_type
    #H：表示无符号短整数（2字节）→ length
    def pack(self):
        # 消息格式: 消息类型(1字节) + 消息长度(2字节) + 消息体
        return struct.pack('!BH', self.msg_type, self.length) + self.body
    
    @staticmethod
    def unpack(data):
        if len(data) < 3:
            return None, data
        
        msg_type, length = struct.unpack('!BH', data[:3])
        
        if len(data) < 3 + length:
            return None, data
        
        body = data[3:3+length]
        remaining = data[3+length:]
        
        msg = Message(msg_type)
        msg.length = length
        msg.body = body
        
        return msg, remaining

# ErrorMessage消息
class ErrorMessage(Message):
    def __init__(self, error_type=None):
        super().__init__(MessageType.ERROR_MESSAGE)
        self.error_type = error_type or 0
        
        # 设置消息体和长度
        self.body = bytes([self.error_type])
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.ERROR_MESSAGE or len(message.body) != 1:
            return None
        
        error_message = ErrorMessage()
        error_message.error_type = message.body[0]
        return error_message

# ApplicationData消息
class ApplicationData(Message):
    def __init__(self, encrypted_data=None):
        super().__init__(MessageType.APPLICATION_DATA)
        self.encrypted_data = encrypted_data or b''  # 加密的应用数据
        
        # 设置消息体和长度
        self.body = self.encrypted_data
        self.length = len(self.body)
    
    @staticmethod
    def from_message(message):
        if message.msg_type != MessageType.APPLICATION_DATA:
            return None
        
        app_data = ApplicationData()
        app_data.encrypted_data = message.body
        return app_data