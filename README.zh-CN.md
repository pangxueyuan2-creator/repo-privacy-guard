# Repo Privacy Guard

**在 GitHub 仓库公开或分享之前，检查可能泄露的密钥和隐私信息。**

Repo Privacy Guard 是一个离线优先的命令行工具和 GitHub Action。它可以
检查常见服务商密钥、私钥、包含密码的数据库地址、高熵敏感赋值以及危险
文件名。报告只包含文件位置、风险类型和不可逆指纹，不会显示匹配到的密钥。

## 主要用途

公开仓库时，开发者可能误传 `.env`、API Key、访问令牌或私钥。这个工具
可以在上传或公开前进行一次本地检查，降低意外泄露风险。

## 主要功能

- 完全在本地运行，不需要账号、API Key 或网络请求；
- 零运行依赖；
- 检查 OpenAI、GitHub、AWS、Google 和 Slack 等常见凭据；
- 检查私钥、包含密码的数据库地址和 JWT 类内容；
- 检查 `.env`、密钥文件和凭据配置文件；
- 可选检查邮箱地址和国际电话号码；
- 支持文字、JSON 和 SARIF 报告；
- 支持命令行、JavaScript API 和 GitHub Action；
- 不会跟随符号链接进入所选扫描范围之外的位置；
- 默认隐藏疑似密钥内容，避免在终端或 CI 日志中二次泄露；
- 支持 `--staged`：只检查即将提交的 Git index 内容，跳过已删除路径，不执行仓库代码。

## 快速使用

需要 Node.js 20 或更高版本：

```bash
npx --yes github:pangxueyuan2-creator/repo-privacy-guard scan .
```

检查个人信息：

```bash
repo-privacy-guard scan . --personal-data --min-severity low
```

只检查暂存区（即将 commit 的内容）：

```bash
repo-privacy-guard scan . --staged
```

生成 SARIF 报告：

```bash
repo-privacy-guard scan . --format sarif --output result.sarif
```

## 注意

自动化交付门禁可使用：

```bash
repo-privacy-guard scan /immutable/source-snapshot --strict-gate --format json
```

严格模式忽略目标仓库的 `.repoguardignore` 和 `repoguard:allow`，并扫描
`dist`、`vendor`、`node_modules` 等通常跳过的目录。只排除并明确计数根目录
的 `.git` 元数据。二进制、无效 UTF-8、符号链接、读取错误、扫描预算耗尽
或观察到的文件变化会导致不完整结果。`gate.decision` 为小写 `pass`、
`fail` 或 `unknown`，对应退出码 0、1、3；无效请求或操作错误为 2。
已发现阻断风险时，即使扫描不完整也返回 `fail`。自动化必须检查该字段，
不能把空发现列表当作通过。JSON 和 SARIF 都包含完整性与扫描范围。

`--strict-gate --staged` 返回 `unknown`；弱化检测的忽略或关闭熵检查参数
会被拒绝。当前 GitHub Action 保留原接口；严格门禁需显式调用 CLI。
应扫描不可变的源文件快照，在调用端绑定源摘要与工具版本，并设置外部超时。
这项检查不提供原子快照，也不能证明不存在任何格式的密钥。

任何扫描工具都无法保证仓库绝对安全。请同时使用 GitHub 的密钥扫描、服务商
密钥管理和人工代码审查。如果发现真实密钥，应立即去对应平台撤销并重新生成，
仅从 Git 历史中删除并不足够。

完整说明请阅读英文版 [README](README.md)。
