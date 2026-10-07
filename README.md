# chat2local

通过一个 ChatGPT MCP 连接，读写多台电脑上明确共享的文件夹，并在单独授权后执行本机命令。

**版本：0.1.0-alpha.24 · Alpha 预览 · MIT License**

## 1. 功能与边界

| 项目 | 当前实现 |
| --- | --- |
| 文件访问 | 枚举目录；读取、创建、修改不超过 64 KiB 的 UTF-8 文本 |
| 写入保护 | 覆盖前备份；通过 SHA-256 检测并发修改；保留逐次审批模式 |
| 命令执行 | Windows PowerShell；macOS/Linux sh；查询输出、超时、取消及防重复执行 |
| 多设备 | 每台电脑独立身份；调用时明确目标；目标离线不切换到其他电脑 |
| 接入方式 | 自托管 Cloudflare Workers / Durable Objects / KV；没有默认公共中继 |
| 运行依赖 | 客户端随包提供 Node.js；不依赖 DevSpace、Codex、ngrok 或 Google 登录 |

**终端不是操作系统沙箱。** 命令以桌面用户权限运行，可以访问共享目录之外的文件、使用网络和删除文件；文件工具的备份与路径限制不适用于命令副作用。仅向可信客户端开放。网关可以接触转发内容，不提供针对网关运营者的端到端加密。[权限说明](docs/PERMISSIONS.md) · [安全边界](SECURITY.md)

## 2. 选择入口

| 你的情况 | 操作 | 是否需要重新配对 |
| --- | --- | --- |
| 从未使用，没有自己的实例 | 执行下方“首次创建实例” | 首次登记设备并完成 ChatGPT 授权 |
| 已有实例，要加入一台新电脑 | 在新电脑执行带实例地址的命令 | 新电脑独立登记；不新建 ChatGPT 插件 |
| 这台电脑已连接，只是断网、重启或关闭程序 | 打开已安装的 Chat2Local 入口 | 本机身份仍有效时不需要 |
| 只要新增共享目录 | 打开管理页，添加目录并确认 | 不需要安装密码或重新安装 |
| 文件可用，命令待授权 | 核对本机命令许可、OAuth scope 和 ChatGPT 工具列表 | 不重选已有目录 |
| 更新软件 | 按[升级说明](docs/OPERATIONS.md#3-升级)区分客户端、云端和 ChatGPT 工具 | 不重置已有身份或权限 |

## 3. 首次创建实例

### 前提

需要自己的 Cloudflare 账号，以及能够添加相应自定义 MCP 应用的 ChatGPT 账号/工作区。平台可用性、写入能力和工具刷新方式以账号实际入口及 [OpenAI 官方说明](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt) 为准；安装本项目不会解锁平台未开放的权限。

### Windows 10+：普通 PowerShell

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1')))
```

### macOS：普通终端，不使用 sudo

```sh
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/jianmosier/chat2local/main/install.sh | sh
```

入口下载固定版本源码和官方 Node 运行环境，校验 SHA-256 后执行配置。首次自托管依次完成：Cloudflare 登录、资源创建确认、本机安装、ChatGPT MCP 配置、本机目录授权、实例安装密码设置。云服务条款和可能产生的费用由实例所有者决定。详细步骤见[首次安装](docs/GETTING_STARTED.md#2-首次创建实例)。

**当前尚未完成全新第三方 Cloudflare 账号的完整端到端验收。** 失败后保留已有配置与错误信息，不删除身份数据、不重复创建云资源。

## 4. 新增电脑

使用原实例地址，不创建另一套网关。以下 `YOUR-INSTANCE` 必须替换为自己的实例域名，不能直接照抄。

Windows：

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1'))) -Instance 'https://YOUR-INSTANCE.workers.dev'
```

macOS：

```sh
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/jianmosier/chat2local/main/install.sh \
  | sh -s -- --instance 'https://YOUR-INSTANCE.workers.dev'
```

在新电脑的浏览器输入实例安装密码，选择本机目录并确认。原有电脑不必在线；不复制设备密钥，不传邀请 JSON，不重复创建 ChatGPT 插件。日常管理不再要求安装密码。

| 地址 | 用途 |
| --- | --- |
| `https://YOUR-INSTANCE.workers.dev` | 安装命令的实例参数 |
| `https://YOUR-INSTANCE.workers.dev/mcp` | ChatGPT 应用的 MCP 端点 |

## 5. 日常打开与回连

Windows：按 Win+R，输入：

```text
%LOCALAPPDATA%\Chat2Local\Chat2Local.cmd
```

macOS：

```sh
open "$HOME/Applications/Chat2Local.command"
```

关闭管理网页不停止后台程序。网络恢复后客户端使用原身份自动重连。主动退出程序后需重新打开入口。管理页“更新与启动”中的“登录后自动连接”控制系统登录后的启动，不是开机登录前的系统服务。

断连、OAuth 失效、身份丢失是不同问题。按[回连故障表](docs/OPERATIONS.md#2-断连与恢复)处理，不把重新安装或重新配对作为默认修复。

## 6. 验证是否可用

按顺序核对：

1. `list_devices`：目标电脑在线，多设备时明确 `deviceId`。
2. `list_roots`：目标目录存在，文件权限符合预期。
3. 文件读写：先检查当前会话实际提供的工具，使用专用测试文件和返回的哈希验证。
4. 终端：工具列表包含三个终端工具，且 `terminalLocalEnabled`、`terminalScopeGranted`、`terminalAllowed` 均为 `true`；再执行无副作用命令并查询退出码。

服务器声明、ChatGPT 保存的工具列表、当前会话工具和本次 OAuth 权限分别核对。不能用其他插件执行成功，替代 Chat2Local 实际调用验收。

## 7. 文档

| 文档 | 内容 |
| --- | --- |
| [安装与配对](docs/GETTING_STARTED.md) | 首次部署、新增设备、已配对设备、成功判据 |
| [运维与恢复](docs/OPERATIONS.md) | 断连、自启、升级、云端更新、故障表 |
| [架构](docs/ARCHITECTURE.md) | 组件、通信链路、身份与存储、源码目录 |
| [权限](docs/PERMISSIONS.md) / [终端](docs/TERMINAL.md) | 权限交集、目录撤销、命令边界 |
| [请求限流](docs/REQUEST_BUDGET.md) | 正常轮询与安装授权分离；429 处理 |
| [发布](docs/RELEASE.md) / [变更记录](docs/CHANGELOG.md) | 脱敏、测试、版本和产物验证 |

## 8. 开发

```sh
npm ci --ignore-scripts
npm run verify
npm run build:public
npm run release
```

`release` 默认只准备；显式 `--publish --repo OWNER/chat2local` 才写入 GitHub。发布会检查完整测试、脱敏源码清单、三种客户端安装包及远端下载一致性。不会自动部署云端或更新本机客户端。

Windows x64、macOS ARM64、macOS x64 有版本化发布包；源码包含 GNU/Linux 适配，但该平台未达到同等实机验收范围。macOS 签名/公证、真实整机重启、全新第三方账号首装及独立安全审计仍是验收项，不以模拟测试替代。
