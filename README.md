# Mihomo Ruleset Builder

自动聚合多个公开规则源，对域名、IP/CIDR 和 Classical 规则进行解析、合并、去重与格式转换，并生成适用于 Mihomo 的规则集。

## ✨ 项目特点

- 自动下载并合并多个上游规则源
- 自动区分 Domain、IP/CIDR、Classical 规则
- 自动域名去重和 IP/CIDR 合并
- 自动生成 Mihomo `.mrs` 规则集
- 自动检测 GitHub HTML 页面污染
- 自动处理 GitHub Raw / jsDelivr 等常见源地址
- 自动生成构建日志
- 自动生成 README 订阅链接
- 自动生成 Mihomo 引用示例
- 自动从规则源 URL 提取并致谢上游作者

## 📦 基础规则

<!-- RULES_START -->
<!-- RULES_END -->

## 📦 合并与去重规则 (ZH)

<!-- RULES_ZH_START -->
<!-- RULES_ZH_END -->

## 🔄 更新与缓存说明

本项目规则由自动化任务定期生成。

GitHub Raw 链接作为推荐的权威下载地址。

jsDelivr CDN 用于加速访问，但由于 CDN 缓存机制，更新后可能短时间内仍返回旧版本规则。
如果发现 GitHub Raw 内容已更新而 CDN 内容仍旧，请优先使用 GitHub Raw，并等待 CDN 缓存刷新。

## ⚠️ 免责声明

本项目仅对公开规则源进行自动化下载、解析、合并、去重及格式转换。

规则内容、准确性、完整性及可用性主要取决于上游规则源，本项目无法保证所有规则在所有网络环境中均正确适用。

使用规则后可能出现误拦截、漏匹配或网络访问异常，请根据实际环境自行调整。

上游规则的版权、许可及相关权益归对应原作者及项目所有。使用本项目生成的规则时，请同时遵守各上游项目的许可证和使用说明。

本项目与 Mihomo、Clash Meta 及各上游规则项目不存在官方隶属关系。

## 🐛 问题反馈

如发现以下问题，欢迎提交 Issue：

- 上游规则源失效
- 规则解析异常
- HTML 页面被误识别为规则
- Domain / IP / Classical 分类异常
- MRS 转换失败
- README 自动生成异常
- 规则明显误匹配或缺失

提交问题时建议附上：

- 出问题的规则组名称
- 上游规则 URL
- `mrs_rules_ZH/build_mrs_zh.log`
- 实际结果
- 预期结果
- Mihomo 版本（如问题与运行结果有关）

Mihomo 本体、代理节点、DNS 环境或代理服务商本身的问题，请优先向对应项目或服务提供方反馈。

## 🤝 参与贡献

欢迎通过 Issue 或 Pull Request：

- 添加新的优质公开规则源
- 修复规则解析问题
- 改进去重逻辑
- 改进 Mihomo 规则转换
- 优化构建日志
- 改进文档和使用示例

详细要求请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 🔐 安全问题

如果发现可能涉及安全风险的问题，请不要在公开 Issue 中披露敏感信息。

请按照 [SECURITY.md](SECURITY.md) 中的说明进行反馈。

## 📄 License

本项目代码的许可方式请参阅 [LICENSE](LICENSE)。

上游规则数据不自动适用本仓库的代码许可证，其版权和许可仍归对应上游项目所有。
