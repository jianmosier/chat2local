# chat2local

**用一个 ChatGPT MCP 连接，访问你自己多台电脑上明确共享的文件夹。**

开源、自托管。每个使用者部署自己的网关；没有作者的默认中继、Google 登录依赖或共享后台。Windows 与 Mac 已有真实设备读写记录；当前仍是 **Alpha 开发预览**，不是经过独立安全审计的成品。

## 一条命令开始

macOS / GNU Linux，在普通用户终端运行（不用 sudo）：

```sh
curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/jianmosier/chat2local/main/install.sh | sh
```

Windows 10+，在普通 PowerShell 运行：

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1')))
```

命令会下载固定版本源码和经过 SHA-256 校验的官方 Node 运行环境，不要求先装 Node、Git、Codex 或 DevSpace。**首次自托管**会打开你自己的 Cloudflare 登录，询问是否创建私人 Worker 与 OAuth 存储，然后配置本机客户端。云服务的账号注册、必要的服务条款和可能产生的用量费用由你自行决定。

这是**一个命令启动并执行配置流程**，不是跳过安全确认：你仍需首次登录云服务、在 ChatGPT 添加生成的 MCP 地址，以及明确确认要共享的目录。不要把安装密码或云端密钥发到聊天里。

## 第二台电脑

在新电脑使用同一个入口并指定自己的实例地址。无需第一台电脑在线，不传邀请 JSON，不复制设备密钥：

```sh
curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/jianmosier/chat2local/main/install.sh | sh -s -- --instance 'https://YOUR-INSTANCE.workers.dev'
```

```powershell
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1'))) -Instance 'https://YOUR-INSTANCE.workers.dev'
```

首次加入新设备，在该设备的浏览器输入**自己的实例安装密码**，选择真正需要的目录并确认。这个密码只用于新增设备接入，不是文件访问令牌。日常追加目录不走这条安装登录流程。

## 日常使用：不用再安装、登录或配对

安装后保留稳定的 **Chat2Local 启动入口**；Mac 位于用户的 `~/Applications/Chat2Local.command`。打开它即进入当前电脑的共享目录管理。也可重复运行安装入口，程序验证并复用或受控更新已有安装，不重置设备身份或目录。

在管理页中可以连续勾选多个目录、分别选择读写模式，然后**一次确认整个新增范围**。后台同时更新本机与原连接；原令牌随即可以访问新范围，无需重新创建插件或输入安装密码。页面会显示确实保存的目录和结果。

当前文件工具支持读取、创建及修改不超过 64 KiB 的 UTF-8 文本；覆盖前备份，并用文件哈希避免覆盖别人的新修改。文件工具不支持删除、二进制传输或整盘开放。多设备时必须明确目标电脑，目标离线不会改操作另一台。

## 终端命令（独立授权）

新增 `terminal_execute`、`terminal_status`、`terminal_cancel`。Windows 使用 PowerShell，macOS/Linux 使用 sh；支持异步任务、输出/退出码、超时和取消。稳定 requestId 防止重复请求重放命令，结果未知时不能自动换 ID 重跑。

必须同时具备 `terminal:execute` OAuth scope 和本机针对原连接、目录的终端授权；在共享目录管理页明确启用。**终端不是操作系统沙箱**，以桌面用户权限运行，能够访问目录外文件和网络，也能删除文件；普通文本工具的备份承诺不适用于命令本身。详情见 [终端边界](docs/TERMINAL.md)。

## 当前边界

- 自动自托管适配器目前是 **Cloudflare Workers / Durable Objects / KV**，不是任意隧道供应商的一键适配。
- 无配置的公开客户端不会偷偷使用作者服务。
- 已连接设备的批量目录管理使用本机受保护网页。**在 ChatGPT 对话内直接批准扩大目录范围的交互卡片尚未实现**；模型不能自己调用文件工具提升权限。
- 新增目录和撤销现有目录的协议不同；批量新增已实现，新页面暂未提供全部权限编辑功能。原有本机撤销/暂停接口仍有效。
- 安装/版本/别名路径检查、模拟全新实例及浏览器集成均有测试，但**全新第三方 Cloudflare 账号从零安装、所有操作系统、系统重启与应用签名/公证尚未完整验收**。有错误时保留原配置并返回错误，不伪报成功。
- 云端或操作系统必要的人类授权不能由脚本绕过。连通性、目录授权和实际读写是不同的验收项。

## 开发与发布

```sh
npm ci --ignore-scripts
npm run verify
npm run test:management
npm run build:public
npm run release
# 通过验证、脱敏导出、提交和远端下载校验后发布
npm run release -- --publish --repo YOUR_LOGIN/chat2local
```

完整浏览器套件当前使用 Windows + Edge；跨平台核心测试可单独运行。源码导出采用明确白名单，排除 `wrangler.local.jsonc`、`.artifacts`、个人会话、设备凭据、日志与内部交接记录。公开构建检查不依赖个人配置。

`npm run release` 默认只准备，不写 GitHub；`--publish` 才提交并发布；不存在的仓库需显式 `--create-repo`。以后使用同一个脚本更新版本，不强推、不覆盖旧标签，不上传私人配置。详见 [Release 流程](docs/RELEASE.md)。

详细说明：[使用与部署](docs/GETTING_STARTED.md) · [安全边界](SECURITY.md)。MIT License。
