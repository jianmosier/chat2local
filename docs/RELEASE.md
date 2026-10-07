# 发布与脱敏

适用版本：0.1.0-alpha.24。

## 1. 发布产物

| 产物 | 内容 |
| --- | --- |
| 源码 tar.gz | 白名单源码、测试、公开文档与 `SOURCE-SHA256.json` |
| Windows x64 zip | 客户端程序、官方 Node 运行时、使用说明及构建清单 |
| macOS ARM64 tar.gz | Apple Silicon 客户端 |
| macOS x64 tar.gz | Intel 客户端 |
| 四个 `.sha256` 文件 | 对应上述四个包的 SHA-256 |

共八个 Release 附件。客户端非运行时文件必须与脱敏源码快照一致；下载后的每个附件还须与本地发布输入逐字节一致。

## 2. 正常流程

```sh
npm run release
# 检查完整报告后发布：
npm run release -- --publish --repo OWNER/chat2local --from VERIFIED_REPORT
```

也可用一次命令完成正常全流程：

```sh
npm run release -- --publish --repo OWNER/chat2local
```

默认只准备，不写 GitHub。不存在的仓库只有显式增加 `--create-repo` 才允许创建。已有仓库沿用原历史；不强推、不覆盖已有标签、不替换旧 Release 附件。

| 阶段 | 必须通过 |
| --- | --- |
| 版本检查 | package、lock、协议与两个安装入口版本一致 |
| 回归 | 语法检查及完整测试；失败、跳过、超时不计为通过 |
| 输入冻结 | 测试前后、构建前后源码 fingerprint 一致 |
| 脱敏导出 | 仅允许列表中的文件；公开正文扫描通过 |
| 客户端构建 | 三平台包齐全，源码对应，运行时校验通过 |
| GitHub 提交 | 使用受控独立发布工作区；noreply 提交身份；远端 HEAD 核对 |
| 附件发布 | 先上传草稿，下载全部附件验证后才公开 |

Windows 的发布 clone 在第一次 checkout 前设置 `core.autocrlf=false` 与 `core.eol=lf`，防止系统 Git 自动改换行；不修改用户全局 Git 配置。

`--from` 只接受版本、完整测试记录、fingerprint 和全部哈希仍一致的报告。失败任务先核对已完成阶段，不直接重跑可能已推送或已创建的发布操作。

## 3. 脱敏规则

公开清单由 `scripts/build-public.mjs` 管理。文档清单也参与发布 fingerprint，新增文档必须纳入清单，不能只在本地写好但漏发。

排除：私有部署配置、`.artifacts`、`.wrangler`、内部交接、设备凭据、本机状态、日志、备份、实际终端输出与未批准的辅助脚本。默认中继必须为空。

检测分两层：

1. 通用规则：私钥与常见令牌特征、设备主机名等；公开规则本身不能包含维护者的具体个人值。
2. 私有输入：从构建机及本地私有部署配置读取实际值；其他设备的敏感值可放入 `.artifacts/publication-private-values.json` 字符串数组，绝不导出或打印内容。

扫描错误只报告文件与类别，不输出命中的秘密。使用合成数据编写测试，不把真实主机名改写成测试常量。

公开 GitHub 用户名、MIT 署名及 GitHub noreply 邮箱属于项目公开身份，不等同于私人联系邮箱、设备身份或云凭据。

## 4. 审计范围

```sh
npm run audit:public -- --tree PATH_TO_EXPORTED_SOURCE
npm run audit:public -- --git PATH_TO_PUBLIC_CHECKOUT
```

树扫描检查指定公开目录；Git 扫描检查该 checkout 中可达的所有已获取引用、提交元数据及 blob，不会访问未获取的远端引用。输出统计、文件/对象位置与失败类别，不输出原始敏感内容。扫描器不自动改写文件、历史或远端仓库。

新版本通过不等于旧提交、旧标签、旧安装包、第三方 fork 或缓存全部清理。发现有效密钥时应优先由所有者撤销/轮换；历史改写和旧附件处理必须单独制定范围并验证，不能因删除当前文件就宣布泄漏消失。

同一托管来源的 SHA-256 不等于独立签名或供应链攻击防护。当前签名/公证、独立可复现构建和外部安全审计尚未完成。

## 5. 软件同步验收

发布 GitHub 不自动部署 Worker，也不自动替换客户端。依照 [OPERATIONS.md](OPERATIONS.md#3-升级)，分别记录：

| 对象 | 证据 |
| --- | --- |
| GitHub main | 提交 SHA |
| Release | 标签、是否公开、八个附件及哈希 |
| 云端 | `/healthz.version`、`requestBudgetVersion`、实际部署记录 |
| Windows/macOS | 实际运行版本、身份与目录保持、实际工具调用 |
| 安装入口 | 脚本版本、包版本、固定源码 URL 与下载校验 |

离线设备、未进行的真实重启和未测试的新账号首装明确标注未验收，不以模拟或构建通过替代。
