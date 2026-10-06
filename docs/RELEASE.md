# 脱敏与 GitHub Release

`npm run release` 是统一发布入口。它只处理公开源码副本，不上传开发目录，不部署私人云端、不改变本机授权，也不自动公开私人 GitHub 仓库。

## 常用命令

```sh
# 运行语法和完整回归，导出脱敏副本、源码压缩包与 SHA-256；不写 GitHub
npm run release

# 完成以上步骤后提交到自己的 GitHub 仓库并创建开发预览 Release
npm run release -- --publish --repo YOUR_LOGIN/chat2local

# 仅在确实还没有该仓库时，显式允许创建这个公开目标
npm run release -- --publish --repo YOUR_LOGIN/chat2local --create-repo

# 上一步已经准备成功，只继续发布：报告必须仍匹配最新源码和测试
npm run release -- --publish --repo YOUR_LOGIN/chat2local --from PATH_TO_PUBLICATION_REPORT
```

省略 `--repo` 时从已经登录的 GitHub CLI 读取用户名，默认目标是该用户名下的 `chat2local`，不会假定维护者账户。需要事先通过 `gh auth login` 正常登录。执行脚本不读取、打印或复制 GitHub 凭据；Git 使用正常 credential helper。

每个发布版本必须唯一。更改 package.json、package-lock.json、src/shared/protocol.mjs 和两个 bootstrap 的版本，保持一致。已存在的标签和 Release 不覆盖；新版本在原远端历史上正常提交，不 force-push。首次导入不带内部调试历史。

## 四个阶段

1. **验证**：语法检查及完整测试分成三个互不重复的批次。测试前后计算输入摘要，源码同时被别人修改就停止。没有 `--skip-tests` 发布开关。
2. **脱敏构建**：明确白名单复制源码、测试、通用说明和安装脚本；排除私人部署、目录授权、设备身份、令牌、日志、内部交接、下载及构建缓存。扫描当前部署 ID/域名和凭据特征；发现疑似泄露则停止，不盲目替换业务源码。没有配置的客户端不默认连接作者实例。
3. **版本更新**：在独立的 Git 工作目录操作。已有仓库须具备上一次 SOURCE-SHA256.json；核对旧公开文件未被另行修改，按新清单更新。只删除之前明确由发布器管理且本版已去掉的文件，保留其他文件和 Git 历史。提交使用 GitHub noreply 邮箱。
4. **远端验收**：推送后核对远端 commit；创建 Draft Release 并上传源码 tar.gz 与 SHA-256；下载已上传文件逐字节/摘要核对，通过后才公开为 prerelease。脚本写出 published.json 记录结果。

`--from` 只接受与当前源码、版本、完整测试和压缩包哈希匹配的报告，不拿过期导出包冒充新版。发布中断不自动删除工作目录、修改标签或重放创建操作；根据实际阶段核对远端后继续，不能只看某一个 subprocess 退出码就宣称全部发布成功。

## 不属于这个脚本的承诺

当前自动化验证不等于所有物理平台和陌生 Cloudflare 账号已经实测。Release 默认标为 Alpha prerelease，不是安全认证、应用签名或 Mac 公证。发布到 GitHub 也不等于已部署维护者实例，更不等于用户的 ChatGPT 会话已加载新工具。

脱敏扫描是工程防护而非任意秘密的完美检测器。不要将新密钥写进源码；自定义扩展白名单前先检查待发布内容。
