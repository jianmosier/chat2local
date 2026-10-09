# Chat2Local

通过一个 ChatGPT MCP 连接，访问自己多台电脑上的文件和终端。

[首次配对](#1-首次配对) · [回连](#2-回连) · [多设备连接](#3-多设备连接) · [管理](#4-管理)

## 1. 首次配对

首台电脑需要创建自己的 Cloudflare 私人网关，并在 ChatGPT 添加连接。请准备自己的 Cloudflare 账号及资源创建权限，确认 ChatGPT 账号或工作区提供自定义 MCP 应用入口。账号、云端资源及用量费用由自己管理。

安装包自带 Node.js，无需预装 Git、Codex 或 DevSpace。用普通桌面用户安装，不使用管理员终端或 sudo。

<details>
<summary>Windows：在 PowerShell 安装</summary>

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1')))
```

</details>

<details>
<summary>macOS：在终端安装</summary>

```sh
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/jianmosier/chat2local/main/install.sh | sh
```

</details>

1. 按提示登录自己的 Cloudflare，确认创建私人网关并安装本机客户端。
2. 把程序输出的完整 `/mcp` 地址添加到 ChatGPT，按平台流程完成 OAuth 授权，在本机授权页选择目录并确认。
3. 按提示在浏览器设置实例安装密码，供新电脑加入使用；它不是文件访问令牌，日常回连也不需要它。

实例根地址（如 `https://your-instance.example.com`）用于安装；`https://your-instance.example.com/mcp` 用于 ChatGPT。示例域名须替换为自己的地址。

在 ChatGPT 中要求列出电脑和共享目录，核对目标在线、目录正确。文件工具支持不超过 64 KiB 的 UTF-8 文本读取、创建和修改；终端需另外授权。**终端不是操作系统沙箱，可能操作共享目录之外的文件和网络。**

首装中断时保留已有身份、配置和错误信息，核对失败阶段后继续原实例，避免重复创建网关。不要把安装密码或设备凭据粘贴到聊天中。

## 2. 回连

已配对电脑在正常断网、休眠或重启后不需重新配对。后台程序仍运行且身份有效时自动回连；主动退出后，重新打开本机入口即可。

Windows 按 Win+R，输入：

```text
%LOCALAPPDATA%\Chat2Local\Chat2Local.cmd
```

macOS 在终端执行：

```sh
open "$HOME/Applications/Chat2Local.command"
```

关闭管理网页不会停止后台程序。管理页“更新与启动”中的“登录后自动连接”控制用户登录后的启动，不是登录前的系统服务；未开启时需手动打开入口，升级保留原开关。

ChatGPT 要求重新授权时处理原 MCP 连接，不删除本机身份或重选目录。更换系统用户、重装系统、丢失身份或撤销设备后，需核对旧记录再重新接入。遇到 429 按服务端提示等待，不反复安装。

回连不会重放结果未知的写入或命令。先查询原请求状态，再核对实际结果。

## 3. 多设备连接

在新电脑加入**同一个实例**，继续使用原 ChatGPT 连接。每台电脑独立保存身份，旧电脑不必在线，不复制旧设备密钥，也不需要传递邀请 JSON。

把下面的 HTTPS 示例替换为原实例根地址，安装参数不加 `/mcp`。

<details>
<summary>Windows：加入已有实例</summary>

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1'))) -Instance 'https://your-instance.example.com'
```

</details>

<details>
<summary>macOS：加入已有实例</summary>

```sh
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/jianmosier/chat2local/main/install.sh \
  | sh -s -- --instance 'https://your-instance.example.com'
```

</details>

在新电脑浏览器输入实例安装密码，选择这台电脑的目录并确认。新设备的共享与命令权限独立授权；原记录完整的电脑再次打开入口时复用原身份。

多台电脑在线时，调用必须明确目标电脑；目标离线不会改在另一台执行。

## 4. 管理

打开本机启动入口进入共享文件夹管理页，不收藏带临时令牌的管理网址。

- **目录与权限**：选择目录后核对确认内容。当前新增默认“完整共享”包含读写和本机命令许可；旧授权不会自动升级。
- **移除共享**：撤销访问，不删除磁盘文件。移除父目录保留独立授权的子目录；移除子目录时需一并撤销仍覆盖它的父目录共享，影响范围以确认框为准。
- **暂停与退出**：暂停控制本机访问，退出停止客户端；两者都不同于移除目录或删除文件。
- **更新客户端**：使用“更新与启动”提供的命令，核对原实例，更新后检查身份、目录、权限和自启。繁忙、暂停或未知进程会阻止升级，不批量终止进程。
- **更新云端**：实例所有者从对应源码版本单独更新原 Worker，保留域名、存储绑定和凭据。安装页、脚本和客户端包也需版本一致；客户端更新不代表云端已更新。

<details>
<summary>架构、开发与安全边界</summary>

通信链路：ChatGPT → HTTPS / MCP / OAuth → 自己的 Cloudflare Worker → 各电脑主动建立的 WSS → 本机 Node.js Agent → 文件或终端服务。本机管理页只监听回环地址，不应暴露到公网；第一台电脑不是其他设备的转发服务器。

`src/agent/` 管理本机连接、文件、终端和身份；`src/relay/` 处理 Worker 路由、Device/Registry Durable Objects 与 OAuth KV；`src/shared/` 定义协议和权限。终端通过 Node.js `child_process.spawn` 启动 PowerShell 或 sh。Agent 不运行本地大模型，也不依赖 DevSpace。

文件访问取 OAuth scope、连接共享范围和本机策略的交集。终端还要求 `terminal:execute`、直接可写共享和明确的本机命令许可。文件可用而命令不可用时，分别检查这些权限及 ChatGPT 实际加载的工具列表；更新不会自动扩大 scope 或刷新工具。

文件工具检查路径、链接、敏感文件名、大小和文本类型，写入比较哈希并在覆盖前备份，不提供删除或二进制传输。这些检查不能隔离同用户恶意软件，路径竞争仍需加固；备份尚无完整保留和恢复界面。

终端以桌面用户权限运行，文件过滤与备份不适用于命令副作用。保留的终端仍可能访问已撤销共享的路径。取消不回滚已有影响，不保证终止脱离的后代进程；云端令牌撤销不保证立即停止运行中的命令。结果未知时用原 `requestId` 查询，不换 ID 重跑。

网关可接触转发正文，不提供针对运营者的端到端加密。正文不主动保存为云端文件，但 OAuth、授权和协调状态会持久化；不要开启正文日志。Windows 敏感状态用当前用户 DPAPI，其他平台主要依靠用户目录权限。凭据、备份和命令日志不公开上传，安全问题通过私密渠道提供脱敏复现。

开发验证使用 `npm ci --ignore-scripts`、`npm run verify`；公开导出用 `npm run build:public`；使用说明仅保留本 README，另带 LICENSE 许可文件。`npm run release` 默认只准备，发布需显式指定 `--publish` 和目标仓库。扫描规则、源码清单及安装包哈希均需通过检查，维护配置和内部记录不导出。修正源码不会清除旧提交或发布包；HTTPS 与同源哈希校验也不替代独立签名。

</details>

<details>
<summary>Alpha 版本与验收范围</summary>

源码版本：**0.1.0-alpha.26**，MIT License。源码版本不表示远端发布包或现有实例已经更新。

Windows x64、macOS ARM64/x64 有打包支持；GNU/Linux 源码适配未达到同等实机验收范围。全新第三方账号首装、真实整机重启、长期无人值守、macOS 签名/公证、独立可复现构建及独立安全审计尚未完成完整验收。本地模拟通过不能代替这些结果，ChatGPT 可用入口以账号或工作区实际开放为准。

</details>
