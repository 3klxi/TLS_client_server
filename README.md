# 简化版 TLS 协议通信系统

本项目实现了一个简化版的 TLS 协议客户端和服务端，支持基于 RSA 的握手认证及 AES 对称加密通信。适合教学演示与网络安全实验使用。

---

## ✨ 功能特性

- ✅ 模拟 TLS 握手流程（非标准协议）
- ✅ 客户端与服务端公钥验证机制
- ✅ 会话密钥协商与 HMAC 验证
- ✅ 建立加密通道后进行双向通信
- ✅ 支持 Wireshark 抓包分析

---

## 🔧 使用说明

### 1. 生成 RSA 公私钥对

**服务端生成密钥：**

```bash
openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:1024
openssl rsa -pubout -in server_private.pem -out server_public.pem
````

**客户端生成密钥：**

```bash
openssl genpkey -algorithm RSA -out client_private.pem -pkeyopt rsa_keygen_bits:1024
openssl rsa -pubout -in client_private.pem -out client_public.pem
```

---

### 2. 安装依赖

使用 pip 安装项目所需依赖：

```bash
pip install -r requirements.txt
```

---

### 3. 配置可信公钥哈希

打开 `client.py` 文件，配置服务端公钥的 SHA-256 哈希：

```python
trusted_pubkey_sha256 = "YOUR_SERVER_PUBKEY_HASH"
```

获取公钥哈希示例命令：

```bash
openssl rsa -pubin -in server_public.pem -outform DER | openssl dgst -sha256
```

将输出的哈希值（去掉 `(stdin)= `）粘贴到代码中。

---

### 4. 启动服务器

```bash
python server.py [host] [port]
```

* 默认 host 为 `localhost`
* 默认 port 为 `8443`

---

### 5. 启动客户端

```bash
python client.py [host] [port]
```

* 默认连接到 `localhost:8443`

---

## 📡 抓包分析（可选）

你可以使用 Wireshark 抓包分析 TLS 通信过程：

1. 选择 `Adapter for loopback traffic capture` 适配器（本地通信）

2. 设置过滤器为：

   ```
   tcp.port == 8443
   ```

3. 可以观察：

   * 握手过程中的 ClientHello、ServerHello、证书传输等消息
   * 加密数据传输阶段的 TCP 包
   * HMAC 校验字段

> 注意：由于是本地回环通信，必须使用 Npcap 支持的 Loopback 适配器才能抓包成功。

---

## 📁 项目结构

```
.
├── client.py                 # 客户端主程序
├── server.py                 # 服务端主程序
├── crypto.py                 # 加解密与签名函数
├── common.py                 # 通用消息封装与类型定义
├── client_messages.py        # 客户端相关消息结构
├── server_messages.py        # 服务端相关消息结构
├── client_private.pem        # 客户端私钥（需自行生成）
├── client_public.pem         # 客户端公钥（需自行生成）
├── server_private.pem        # 服务端私钥（需自行生成）
├── server_public.pem         # 服务端公钥（需自行生成）
├── requirements.txt          # 依赖包列表
└── README.md                 # 使用说明文档
```

---

## ⚠️ 注意事项

* 本项目为教学与实验用途，不适用于生产环境。
* 通信过程未实现真正的 TLS 加密层和证书链校验，仅模拟握手流程。
* 若要增强安全性，可考虑集成 X.509 证书、ECC 密钥交换、TLS1.3 等标准协议元素。

---

## 📮 联系我

如有建议、Bug、使用问题，欢迎通过以下方式联系我：

📧 邮箱: karenxindongle@126.com
📌 或提交 Issue / PR 到本仓库
