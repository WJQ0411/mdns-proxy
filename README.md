# mDNS Proxy

一个轻量级的mDNS代理程序，用于跨子网转发mDNS服务发现报文。

## 使用场景

服务位于子网A，通过端口转发代理到子网B。为了让子网B的客户端能够发现并正确访问该服务：

1. 服务在子网A发送mDNS通告（包含服务的真实IP）
2. 代理从 `src-iface` 接收mDNS报文
3. 转发到 `dst-iface`（子网B），同时修改：
   - **包源IP** → 改为 `dst-iface` 的IP（代理主机）
   - **A记录IP** → 改为 `dst-iface` 的IP（代理主机）
4. 子网B的客户端发现服务，连接到代理主机
5. 代理主机通过端口转发将流量转发到实际服务

## 工作原理

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Service    │      │    Proxy    │      │   Client    │
│ (Subnet A)  │──────│(Dual-stack) │──────│(Subnet B)   │
│             │      │             │      │             │
│ 10.0.1.100  │      │eth0:10.0.1.1│      │  10.0.2.50  │
│             │      │eth1:10.0.2.1│      │             │
└─────────────┘      └─────────────┘      └─────────────┘

服务发送mDNS: src=10.0.1.100, A记录=10.0.1.100
     ↓
代理转发到eth1: src=10.0.2.1, A记录=10.0.2.1
     ↓
客户端收到: 服务在10.0.2.1，连接到10.0.2.1
     ↓
代理通过端口转发将流量转发到10.0.1.100
```

## 特性

- 双向转发mDNS报文（UDP 5353端口）
- NAT风格的IP修改：
  - 修改包源IP为目标网卡IP
  - 修改DNS A记录为目标网卡IP
- 使用libpcap捕获和注入原始网络包
- 支持Docker部署

## 构建

### 本地构建

```bash
# 安装依赖（Ubuntu/Debian）
sudo apt-get install libpcap-dev

# 构建
go build -o mdns-proxy

# 运行（需要root权限）
sudo ./mdns-proxy -src-iface eth0 -dst-iface eth1 -verbose
```

### Docker构建

```bash
docker build -t mdns-proxy .
```

## 使用方法

### 命令行参数

- `-src-iface`: 源网络接口（服务所在子网的接口）
- `-dst-iface`: 目标网络接口（客户端所在子网的接口）
- `-verbose`: 启用详细日志

### 本地运行

```bash
# 从服务子网转发到客户端子网
sudo ./mdns-proxy -src-iface eth0 -dst-iface eth1
```

### Docker运行

```bash
docker run -d \
  --name mdns-proxy \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  mdns-proxy -src-iface eth0 -dst-iface eth1
```

### Docker Compose

编辑 `docker-compose.yml` 中的接口名称：

```yaml
command:
  - "-src-iface=eth0"
  - "-dst-iface=eth1"
```

启动：

```bash
docker-compose up -d
```

## 权限要求

程序需要以下权限：
- **root权限**：捕获和注入网络包
- **CAP_NET_RAW**：使用原始套接字
- **CAP_NET_ADMIN**：网络管理操作

Docker容器需要：
- `--network host`：使用主机网络
- `--cap-add NET_ADMIN`：网络管理能力
- `--cap-add NET_RAW`：原始套接字能力

## 典型应用

- **跨子网服务发现**：让不同子网的客户端可以发现服务
- **IoT设备发现**：跨网段发现Chromecast、AirPlay等设备
- **开发测试环境**：在隔离网络中进行服务发现测试

## 注意事项

1. **接口配置**：确保 `src-iface` 连接服务子网，`dst-iface` 连接客户端子网
2. **端口转发**：需要配置端口转发规则，将流量从代理主机转发到实际服务
3. **多播支持**：确保网络允许mDNS多播流量（224.0.0.251）
4. **防火墙**：可能需要配置防火墙允许UDP 5353端口
5. **代理**: 本程序仅代理mDNS用作设备发现，仍需Lucky等的反向代理/端口转发等功能代理源服务

## 许可证

MIT License
