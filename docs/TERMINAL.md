# 终端执行

适用版本：0.1.0-alpha.24。

## 1. 工具与前提

| 工具 | 作用 |
| --- | --- |
| `terminal_execute` | 启动非交互命令 |
| `terminal_status` | 查询状态、输出和退出码 |
| `terminal_cancel` | 请求终止任务及附着的进程树 |

Windows 使用 PowerShell，macOS/Linux 使用 `/bin/sh`。不提供 PTY、持续输入流、提权提示或 SSH 会话管理。

必须同时具备 `terminal:execute` OAuth scope、原连接下直接可写的共享目录，以及绑定到该连接和目录的本机命令许可。先读取目标设备的 `list_roots`，确认 `terminalAllowed=true`；当前会话也必须实际提供三个工具。

## 2. 调用

每项有意执行的命令分配一个 UUID。以下为参数模板，标识符必须来自实际设备和目录查询：

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

`running` 不是成功。用相同 `deviceId`、`rootId`、`requestId` 查询，直到取得终态。`succeeded` 且退出码为 0 表示正常退出，不代表业务逻辑正确。

| 结果 | 处理 |
| --- | --- |
| `running` | 查询同一任务 |
| `succeeded` | 核对输出及业务结果 |
| `failed` / `timed-out` / `cancelled` | 检查已有影响，不假设自动回滚 |
| `interrupted` / 结果未知 | 核对实际状态，不更换 ID 盲目重放 |

任务在 spawn 前持久化。同 ID、同参数只返回原任务；同 ID 换参数会被拒绝。客户端重启不自动执行未完成任务。

## 3. 限制

| 项目 | 限制 |
| --- | --- |
| 命令文本 | 最多 16 KiB |
| 保留输出 | stdout 与 stderr 合计 64 KiB；超量标记截断 |
| 超时 | 100–300000 毫秒，默认 120000 |
| 并发 | 每个客户端进程最多两个任务 |
| 任务日志 | 最多 2048 条；满时拒绝新命令，不删除防重放证据后重新执行 |

不向子进程直接传递完整服务环境，只传递运行所需的标准变量。升级器拒绝在任务仍运行时切换客户端。

## 4. 安全边界

**不是操作系统沙箱。** cwd 只决定起始目录。命令以桌面用户权限运行，能够访问目录之外的文件、网络及该用户可读取的秘密，也可能删除文件。文件工具的路径过滤、64 KiB 文件上限及覆盖前备份不适用于命令副作用。

取消和超时请求终止附着的进程树或进程组；自行脱离的后代不保证被终止。暂停、本机撤销或云端令牌撤销不等同于已经回滚命令。停止状态未知时先检查，不反复杀进程。

仅对可信客户端及明确任务开放。不要打印密钥、凭据文件或完整私有日志。权限诊断见 [PERMISSIONS.md](PERMISSIONS.md)。
