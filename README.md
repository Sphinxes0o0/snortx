# snortx

snortx 是一个基于 Go 的 Snort 规则测试工具，用于解析 Snort 规则、生成匹配的 网络数据包、录制到 PCAP 文件，并生成 HTML/JSON 测试报告。

## 功能特性

- **规则解析** - 支持完整的 Snort 规则语法解析
- **数据包生成** - 根据规则生成匹配的 gopacket 数据包
- **PCAP 录制** - 将生成的数据包录制到 PCAP 文件
- **测试报告** - 生成 HTML 和 JSON 格式的测试报告
- **REST API** - 提供 HTTP API 接口
- **并行处理** - 基于 Worker Pool 的并行规则处理
- **端口扫描** - 提供 nmap/masscan 风格的高并发 TCP 端口扫描
- **高速灌包** - 提供 hping3 风格的高并发定制包灌流能力

## 支持的协议

TCP, UDP, ICMP, IP (IPv4/IPv6), SCTP, DNS, ARP

应用层协议标识符（http, https, ftp, ssh, smtp, dns 等）会自动映射为 TCP 传输。

## 快速开始

### 构建

```bash
# 构建 CLI
go build -o snortx ./cmd/cli

# 构建 API 服务器
go build -o snortx-api ./cmd/api
```

### CLI 命令

```bash
# 解析规则
./snortx parse examples/sample.rules

# 生成数据包（不发送）
./snortx generate examples/sample.rules

# 验证规则（不生成数据包）
./snortx lint examples/sample.rules

# 运行完整测试管道
./snortx test examples/sample.rules -o /tmp/output

# 批量测试多个文件
./snortx batch rules1.rules rules2.rules

# 启动 API 服务器
./snortx-api serve --addr :8080

# nmap/masscan 风格扫描（高并发）
./snortx scan 192.168.1.0/24 --top-ports 20 --workers 1024 --rate 2000

# hping3 风格高速灌包
./snortx flood 10.0.0.10 --protocol tcp --port 80 --tcp-flags syn --workers 8 --rate 50000 --duration 10s --engine pcap
```

### REST API

启动服务后访问 `http://localhost:8080/api/v1/health` 健康检查

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/rules/upload` | 上传规则文件 |
| POST | `/api/v1/rules/parse` | 解析规则文本 |
| POST | `/api/v1/tests/run` | 运行测试管道 |
| GET | `/api/v1/tests/results?id=<id>` | 获取测试结果 |
| GET | `/api/v1/health` | 健康检查 |

说明：
- `/api/v1/rules/parse` 与 `/api/v1/rules/upload` 会返回 `errors` 数组用于透传逐行解析错误。
- `/api/v1/tests/run` 当规则全部解析失败时返回 `400`，部分失败时在响应 `parse_errors` 中返回明细。

发送引擎：
- 当前默认 `pcap`（稳定可用）。
- `sendmmsg` / `afpacket` 引擎已预留 CLI/配置入口，后续版本实现。

### 配置文件

snortx 使用 YAML 配置文件：

```yaml
app:
  name: snortx
  version: "1.0.0"

engine:
  worker_count: 0  # 0 = 自动 (NumCPU)
  rule_timeout: 30s
  total_timeout: 5m
  output_dir: ./output
  generator:
    default_src_ip: "192.168.1.100"
    default_dst_ip: "10.0.0.1"
    default_src_port: 12345
    default_dst_port: 80

api:
  address: ":8080"
  cors_allowed_origins:
    - "*"
```

## 架构

```
cmd/cli, cmd/api     → 入口点
internal/rules       → Snort 规则解析（Parser, models）
internal/packets     → 数据包生成（Generator）和 PCAP 写入（Sender）
internal/engine      → 并行规则处理的 Worker Pool
internal/reports     → JSON 和 HTML 报告生成
internal/api         → HTTP 服务器、处理器、路由（gorilla/mux）
pkg/config           → 配置结构和 YAML 加载
```

**数据流**: Parser → Engine（Worker Pool）→ Generator（创建数据包）→ Sender（写入 PCAP）

**Engine 设计**: 使用 sync.WaitGroup 协调 Worker，sync.Mutex 线程安全聚合结果，缓冲通道（ruleChan, resultChan）大小为 workerCount*2。PCRE 模式使用内存缓存。

## 测试

```bash
# 运行所有测试
go test ./...

# 运行单个测试
go test ./internal/rules -run TestParseContentMatch -v
```

## 示例规则

```snort
# TCP 内容匹配
alert tcp any any -> any any (msg:"TEST TCP content"; content:"test"; sid:1000001; rev:1;)

# HTTP 流量
alert tcp any any -> any 80 (msg:"HTTP traffic"; content:"GET"; nocase; sid:1000005; rev:1;)

# PCRE 匹配
alert tcp any any -> any any (msg:"TEST PCRE"; content:"GET /"; pcre:"/GET /"; sid:1000007; rev:1;)

# 双向流量
alert tcp any any <> any any (msg:"TEST bidirectional"; content:"test"; sid:1000027; rev:1;)
```

## License

MIT
