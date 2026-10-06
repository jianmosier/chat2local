# 终端执行（Alpha）

三个 MCP 工具：`terminal_execute` 启动命令，`terminal_status` 查询输出与退出码，`terminal_cancel` 请求停止。Windows 使用非交互 PowerShell，macOS/Linux 使用 `/bin/sh`。不提供终端输入流、PTY、提权提示或 SSH 会话管理。

## 先明确授权

终端与文件读写是不同权限。必须同时满足：原连接具备 `terminal:execute` OAuth scope；本机共享目录是允许直接读写的目录；用户在本机“共享文件夹 → 终端执行”明确启用了这个连接、这个目录的终端权限。新增 scope 需要原连接的正常 OAuth 授权，旧令牌不会因软件升级、本机开关或工具清单更新自动获得它。当前仍只加载旧工具的会话不能直接调用新工具。

**这不是操作系统级沙箱。** 命令以桌面用户的系统权限运行，可以主动访问工作目录以外的文件、执行删除、启动子进程或访问网络。cwd 限制只决定启动位置，不把命令限制在目录内。普通文本工具的备份、64 KiB 与路径过滤不适用于命令自身产生的文件操作。只对可信客户端与明确任务开启，不要把它当作只读文件权限的升级替代品。

## 调用流程

先 `list_devices` 与指定电脑的 `list_roots`，核对 `terminalAllowed`。每项有意执行的命令生成一个 UUID `requestId`，然后调用：

```json
{
  "deviceId": "EXACT_DEVICE_ID",
  "rootId": "EXACT_ROOT_ID",
  "requestId": "UUID_FOR_THIS_COMMAND",
  "command": "git status --short",
  "cwd": ".",
  "shell": "auto",
  "timeoutMs": 120000
}
```

`terminal_execute` 返回 `running` 不是成功。继续用相同 deviceId/rootId/requestId 查询 `terminal_status`，直到得到 `succeeded`、`failed`、`timed-out` 或 `cancelled`。退出码为 0 且状态成功才代表命令正常退出；它不代表业务结果正确。

请求在启动子进程前持久化。同一个 ID 和相同参数只返回原结果；换命令复用 ID 会被拒绝。网络超时后不要换 ID 自动重跑。进程重启后未完成的日志返回 `interrupted` 和结果不确定，应检查实际效果，而不是假设没执行。

## 边界

单条命令最多 16 KiB，stdout+stderr 合计保留 64 KiB，超量会明确标记截断。超时可设置 100–300000 毫秒，默认 120000；每个客户端进程最多同时执行两个任务。日志保留上限 2048 条，达到上限拒绝新命令，避免静默过期 ID 导致重放。终端输出可能包含敏感信息；不要要求打印密钥或凭据文件。

本机暂停或取消终端授权会触发已知任务停止请求。Windows 使用针对精确子进程的 taskkill /T，POSIX 使用独立进程组；自行脱离进程组/进程树的后代不保证被终止。取消不回滚已经发生的修改；云端令牌撤销也不保证立即停止已经启动的本机命令。停止状态不确定时会如实返回，不反复杀进程或重跑命令。

不向子进程传递完整的服务环境；只传递运行所需的 PATH、用户目录、临时目录等标准变量，不主动传设备令牌、云厂商凭据或 Node 预加载参数。这仍不能隔离同用户进程读取它本来就有权限读取的文件。

升级器拒绝在终端任务运行时切换客户端。先结束任务，再更新；不要把“源代码新增工具”当作“当前 ChatGPT 会话已加载工具”。
