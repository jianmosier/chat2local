# 架构

适用版本：0.1.0-alpha.24。本文只描述当前私人实例模式；旧账号/OIDC、邀请与配对路径保留在源码中用于兼容，不是公开安装的默认流程。

## 1. 组件与通信

```text
ChatGPT
   │ HTTPS /mcp + OAuth
   ▼
Cloudflare Worker
   ├─ OAuth KV：OAuth 元数据与令牌相关记录
   ├─ Registry Durable Object：连接、授权引用、协调与请求额度
   └─ Device Durable Object：设备认证、在线会话及请求转发
                    ▲
                    │ 设备主动建立 WSS
             ┌──────┴──────┐
             │             │
       Windows Agent   macOS Agent
             │             │
       文件 / 终端执行   文件 / 终端执行
             ▲             ▲
       本机管理网页     本机管理网页
       127.0.0.1       127.0.0.1
```

每台电脑主动出站连接网关。第一台电脑不是其他电脑的转发服务器；新增设备不依赖它在线。不要将本机控制端口直接开放到公网。

## 2. 源码职责

| 路径 | 职责 |
| --- | --- |
| `src/agent/main.mjs` | 本机 HTTP 控制器、管理 API、权限变更与工具分发 |
| `src/agent/bridge.mjs` | 设备认证连接、心跳、退避重连、防重复传输 |
| `src/agent/files.mjs` | 路径校验、UTF-8 文本、哈希检查、备份与写入 |
| `src/agent/terminal.mjs` | 命令预留、执行、输出、超时、取消和防重放 |
| `src/agent/store.mjs` | 本机持久化；Windows 私有状态保护 |
| `src/agent/folder-management.mjs` | 已登记设备的目录新增与确认事务 |
| `src/agent/share-removal.mjs` | 本机先撤销、云端同步与同请求恢复 |
| `src/agent/ui/` | 本机浏览器界面；不承载模型推理 |
| `src/relay/worker.mjs` | 公开 HTTP/MCP 入口、OAuth 集成、请求路由 |
| `src/relay/state.mjs` | Device、Registry Durable Objects |
| `src/relay/instance-http.mjs` | 私人实例加入、授权与目录管理协议 |
| `src/relay/request-budget.mjs` | 匿名入口、设备读取和设备变更的独立额度 |
| `src/shared/` | 工具协议、权限模型、共享树及双方通用校验 |
| `scripts/` | 安装、自托管部署、升级、打包、脱敏与发布 |

## 3. 身份与权限

| 对象 | 用途 | 不提供的能力 |
| --- | --- | --- |
| 设备凭据 | 证明某台电脑属于该实例 | 不能复制成另一台设备身份 |
| OAuth 令牌 | 限定 ChatGPT 连接能力 | 不能自行批准新增本机目录或终端 |
| 连接共享记录 | 将设备和目录关联到某个连接 | 不能覆盖本机拒绝或撤销 |
| 本机控制会话 | 允许本机浏览器管理该电脑 | 不是云端文件令牌 |
| 实例安装密码 | 允许新设备加入流程 | 不直接读取已共享文件 |

文件权限取 OAuth scopes、连接共享范围和本机当前策略的交集。终端还要求直接可写的共享及明确的本机命令许可。详细规则见 [PERMISSIONS.md](PERMISSIONS.md)。

本机授权先持久化，再激活对应云端范围。失败或响应丢失时核对同一个请求；不能自动生成新授权或盲目重放写入。

## 4. 数据边界

文件正文经网关转发；网关运营者能够接触正文，因此不是针对运营者的端到端加密。代码不主动把正文持久化为云端业务记录，但会保存 OAuth、权限、哈希及有界协调状态；不能开启载荷日志后仍宣称正文不被记录。

设备身份、目录实际路径、备份、终端输出和本机审计记录属于私有状态，不进入公开源码或安装包。Windows 采用 CurrentUser DPAPI；其他平台目前依赖文件权限。

## 5. 工具边界

| 类型 | 工具 |
| --- | --- |
| 发现与读取 | `list_devices`、`list_roots`、`list_directory`、`read_file` |
| 文件变更 | `propose_write`、`write_file`、`operation_status` |
| 终端 | `terminal_execute`、`terminal_status`、`terminal_cancel` |

文件工具不提供删除和二进制传输。终端不是文件工具的沙箱扩展；以桌面用户身份执行后，可以访问 cwd 之外的文件和网络。多设备必须明确目标，不因目标离线更换设备。

## 6. DevSpace 与本项目的关系

DevSpace 是可选的开发维护通道，不是 Chat2Local 的运行依赖。Chat2Local 的 Node Agent、文件服务、终端服务和云端路由位于本仓库；当前不需要拉取或编译 DevSpace 才能运行。

后续复用 DevSpace 源码属于独立架构变更。评估内容应包括具体上游与许可证、接口边界、依赖成本、升级方式以及现有权限规则是否被保留。不能把“引入另一个 MCP 服务”视为自动获得新的授权。

## 7. 扩展新能力的检查点

新增工具须同时处理工具 schema、OAuth scope、云端校验、本机许可、持久化兼容、用户界面和负向测试。发布后还需处理 ChatGPT 保存的工具快照。服务器声明有工具，不代表当前会话已加载或获准执行。

## 8. 版本与构建

客户端与云端由同一源码版本发布，但独立安装和部署。`/healthz` 返回网关版本及请求额度实现标记；客户端另有自己的版本。发布包包含文件哈希清单，GitHub Release 绑定源码提交。版本号、源码提交、包哈希和实际部署分别核对。
