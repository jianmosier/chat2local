# Chat2Local

**Self-hosted multi-device MCP access with explicit folder and terminal permissions.**

让 ChatGPT、Gemini 等支持自定义 MCP 的应用，安全访问你明确授权的本地电脑目录。支持单个自建云端实例连接多台电脑，按“每个应用 × 每台设备”独立隔离与管理权限。

[核心特性](#核心特性) · [1. 首次配对](#1-首次配对) · [2. 日常回连与使用](#2-日常回连与使用) · [3. 多设备接入](#3-多设备接入) · [4. 权限管理与维护](#4-权限管理与维护) · [开发者指南](#开发者构建与架构说明)

---

## 核心特性

* **多端独立鉴权**：一个 Cloudflare 实例可接入多台电脑；ChatGPT 与 Gemini 各自持有独立的目录共享范围，互不越权。
* **双重显式授权**：本机目录授权与应用共享分离；文件读写与终端命令执行权限严格解耦。
* **安全文件操作**：支持 ≤ 64 KiB 的 UTF-8 文本读写，覆盖前自动校验哈希并保留备份，原生禁用文件删除与二进制传输。
* **原生轻量客户端**：Windows x64 采用 Rust 原生 Agent（无需安装 Rust 编译环境），断网自动通过 WSS 重连。

---

## 1. 首次配对

### 准备工作
* 准备一个 **Cloudflare 账号**（用于部署你自己的云端转发实例）。
* 准备支持添加自定义 MCP 服务的应用账号（如 ChatGPT、Gemini，具体开放条件以各平台当前界面为准）。

### 第一步：部署自建云端实例
首次创建云端实例时，请下载并解压 [同版本源码](https://github.com/jianmosier/chat2local/releases/download/v0.1.0-alpha.30/chat2local-source-v0.1.0-alpha.30.tar.gz)，在源码目录下运行安装脚本：

* **Windows (PowerShell)**：
  ```powershell
  .\install.ps1
  ```
* **macOS (终端)**：
  ```sh
  sh install.sh
  ```

按终端提示登录 Cloudflare 完成实例部署，记录生成的 `/mcp` 专属接入地址。
> **说明**：Windows 自建实例安装器会自动校验并获取同版本 Windows 预编译包，无需本地配置 Rust 编译环境。

### 第二步：启动本机 Agent 并完成配对
1. **下载安装包**：从 [Release 0.1.0-alpha.30](https://github.com/jianmosier/chat2local/releases/tag/v0.1.0-alpha.30) 下载对应系统安装包：
   * **Windows x64**：解压后双击 `start-chat2local.cmd`（日常运行使用 Rust 原生 Agent，内置 Node 仅用于安装与接入）。
   * **macOS**：解压后运行对应启动脚本（继续使用 Node Agent）。
   * *注：本次暂未提供 Windows ARM64 原生安装包。*
2. **添加 MCP 并确认**：将第一步获取的 `/mcp` 地址添加到 ChatGPT 或 Gemini。随后在运行 Agent 的电脑本地面板上，核对请求的应用、电脑、目录及权限并点击确认（首次连接必须在本机完成本地确认）。

---

## 2. 日常回连与使用

### 启动入口
* **Windows**：按 `Win + R`，输入 `%LOCALAPPDATA%\Chat2Local\Chat2Local.cmd` 回车。
* **macOS**：打开用户 `Applications` 目录下的 `Chat2Local.command`。

### 连接机制与排障
* **后台常驻**：Agent 运行期间主动通过 WSS 连接云端，网络恢复后自动回连。**关闭本地管理网页不会停止 Agent**。
* **授权过期处理**：若 AI 应用提示授权过期，请直接在原连接中重新认证；**切勿清空设备身份或手动复制密钥**。
* **本地拒绝连接**：若浏览器跳转 `127.0.0.1` 提示拒绝连接，请先通过上述启动入口拉起本机 Agent；更新或重启后若管理页要求验证，同样从本机启动入口重新打开即可。

### 推荐 Prompt 起手式
开始任务前，建议先让 AI 调用 `list_devices` 和 `list_roots` 确认在线设备、目录及权限。例如：
> “请先调用工具查看当前在线的电脑和已共享目录，读取指定电脑上某项目的 README 并解释项目结构，不要修改任何文件。”

---

## 3. 多设备接入

1. 在管理页打开 **“连接与新电脑”**，复制安装链接。
2. 在新电脑上运行安装程序，输入**实例安装密码**并单独选择该电脑的共享目录。
3. AI 应用端继续使用原有的 `/mcp` 连接即可，无需旧电脑保持在线，也严禁直接复制旧电脑的设备密钥。

**多设备调度原则**：
* 多台电脑同时在线时，请在 Prompt 中明确指定目标电脑名称；若目标电脑离线，系统**不会**自动漂移到其他电脑执行。
* 权限按应用隔离：某个目录授权给了 Gemini，不代表 ChatGPT 自动获得相同权限。

---

## 4. 权限管理与维护

### 目录与终端授权（重要）
在 Rust 原生面板中添加目录需完成**两步配置**：
1. 点击 **“授权一个本机目录”**（仅代表本机允许访问该路径）。
2. 点击 **“共享给应用”**，选择具体连接（如 Gemini 或 ChatGPT），添加目标目录并确认。

* **权限级别**：默认仅勾选“文件读写”；如需运行命令，需单独勾选 **“文件读写和执行命令”**（同时要求应用侧具备终端 OAuth 权限）。已有目录可随时切换为“只读”、“逐次审批”或“直接读写”。
* **移除共享**：移除共享仅收回访问权，完整保留磁盘文件；父子目录重叠时，确认页会列出实际撤销范围。

> ⚠️ **安全与操作边界警告**
> * **终端不是操作系统沙箱**：终端命令以当前系统用户权限直接运行，可访问共享目录以外的文件和网络。终端操作**没有自动备份**，取消任务不会回滚已发生的修改。
> * **文件工具限制**：单文件上限为 **64 KiB UTF-8 文本**，覆盖前强制检查哈希并保留备份；不提供文件删除与二进制传输能力。当操作返回 `pending`、`failed` 或 `unknown` 时，请先让 AI 查询原操作状态，不要重复提交。

### 升级与回退
云端实例与本机客户端分别独立更新。常规更新会完整保留原域名、存储、设备身份和已有权限。

* **如何升级**：在原生面板点击 **“完全退出”**，等待进程彻底退出后再运行新版安装包（暂不支持无人值守升级）。安装器会校验文件并存入独立版本目录，确认新进程正常后原子切换管理入口，旧程序包予以保留。若进程正在运行或归属不明，安装器将拒绝切换（不强停、不重置授权）。*注：若此前开启了旧版“登录启动”，请先在旧面板关闭，升级后再从新面板重新开启。*
* **如何回退**：正常退出 Agent 后，使用当前安装包的 `runtime/node.exe` 执行回退命令（传入保留的原生安装目录绝对路径）：
  ```powershell
  .\runtime\node.exe scripts/install-portable.mjs --rollback "<保留的原生安装目录绝对路径>"
  ```
  回退仅切换已校验的可执行程序，保留当前目录授权、撤销记录、身份和数据，不恢复旧状态文件。若存在未完成写入或进程归属不明，请先排查原问题。

---

## 开发者构建与架构说明

```mermaid
flowchart LR
  A["ChatGPT / Gemini"] -- "MCP / OAuth" --> B["Cloudflare Worker / DO / KV"]
  B -- "WSS" --> C["本机 Rust 原生候选 / Node.js Agent"]
  C --> D["明确授权的文件与终端"]
```

<details>
<summary><b>点击展开：Rust 迁移状态、源码构建与发布流程</b></summary>

### 版本与组件状态
* **版本对齐**：发行包对应固定版本标签，开发分支后续修正不会自动进入旧安装包。GitHub 源码、本机程序和云端实例需分别核对版本（无自动升级）。已有发布记录不代替后续修改的验证。
* **Windows 原生端状态**：当前 Windows Rust 原生候选已覆盖连接重连、文件操作、审批历史、终端、平台适配及本地授权管理（沿用原设置与 `CurrentUser` DPAPI 数据），已在 Gemini 文件读写与 ChatGPT 目录查询中完成实测。当前状态为 `fullAgent=false`、`upgradeReady=false`（通用设备注册、配对码和断开身份入口尚未覆盖；管理页 UI 仍为内嵌的 HTML/CSS/JS）。
* **云端网关状态**：云端 Rust 的 Device、Registry、OAuth 和 OIDC 模块目前为独立构建候选。默认 Cloudflare Worker 保持 JavaScript 实现（现阶段网关以鉴权、存储和网络转发为主，暂未证实云端全面迁移 Rust 的性能收益）。

### 仓库目录结构
* `crates/`：Rust 工作区源码
* `src/agent/`：Node.js 兼容实现
* `src/relay/`：云端网关及 Rust 模块适配
* `scripts/`：构建、校验与公开导出工具

### 本地构建指南
**环境要求**：Node.js `24.14–26`。构建 Windows 原生 Agent 另需 Rust MSVC 工具链、Visual Studio C++ 开发环境，以及已校验的 **OpenSSL 3.5.8 静态产物**。

1. **基础校验**：
   ```powershell
   npm ci --ignore-scripts
   npm run check
   ```
2. **配置 OpenSSL 环境变量**：
   将 `CHAT2LOCAL_OPENSSL_DIR`、`CHAT2LOCAL_OPENSSL_MANIFEST`、`CHAT2LOCAL_OPENSSL_MANIFEST_SHA256` 分别指向安装目录、逐文件 SHA-256 JSON 清单及清单自身的 SHA-256。
   * `install/` 清单必须与安装目录严格对应，至少包含头文件、`libssl.lib`、`libcrypto.lib` 和 `openssl.exe`。
   * 公开发布的 OpenSSL 应使用 `no-filenames` 与通用默认目录构建，避免将私人构建路径编入二进制包（Rust 构建器亦会执行路径重映射与检查）。
3. **编译并启动原生 Agent**：
   ```powershell
   node scripts/build-native-agent.mjs --openssl-dir "$env:CHAT2LOCAL_OPENSSL_DIR" --openssl-manifest "$env:CHAT2LOCAL_OPENSSL_MANIFEST" --openssl-manifest-sha256 "$env:CHAT2LOCAL_OPENSSL_MANIFEST_SHA256"
   .\.artifacts\native-agent\chat2local-native-agent.exe --launch
   ```
   *注意：使用原 Windows 用户和状态目录测试时，请先正常停止旧 Agent，避免双宿主冲突；切勿为切换程序删除授权数据。源码目录运行 `npm start` 仍保留 Node.js 兼容入口，而原生安装包管理入口会直接启动已校验的 Rust 程序且不静默回退。*

### 发布与导出流程
* `npm run build:public`：仅导出清单内的公开文本源码，自动排除个人配置、设备身份、构建缓存与私人交接记录。
* `npm run release`：设置 `CHAT2LOCAL_NATIVE_AGENT_RELEASE_EXECUTABLE` 指向刚构建的原生 EXE 后，运行该命令会强制执行原生验证并打包同源码发布包（默认 Cargo release 模式，内置 Microsoft CRT 与第三方许可证）。
* 正式发布需附加 `--publish --commit` 明确指定已推送并审查的固定 Commit。若后台发布失败，请先核对 GitHub Release、标签与附件状态，切勿盲目自动重试。

</details>

---

## License

Version `0.1.0-alpha.30` · Released under the [MIT License](LICENSE).
