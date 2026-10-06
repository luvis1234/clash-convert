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

### 📦 自动生成的 MRS 规则集订阅链接

> ⏱ **最后同步时间**：`2026-10-06 16:21:11` (UTC+8)

你可以直接在 Mihomo 配置文件中引用以下链接：

| 文件名 | Behavior | 下载链接 |
| :--- | :---: | :--- |
| **AdvertisingTest_Domain.mrs** | `domain` | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_sp/AdvertisingTest_Domain.mrs) <br> [jsDelivr CDN (推荐)](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_sp/AdvertisingTest_Domain.mrs) |
| **ChinaMaxNoIP_Domain.mrs** | `domain` | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_sp/ChinaMaxNoIP_Domain.mrs) <br> [jsDelivr CDN (推荐)](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_sp/ChinaMaxNoIP_Domain.mrs) |
| **Google_Domain.mrs** | `domain` | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_sp/Google_Domain.mrs) <br> [jsDelivr CDN (推荐)](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_sp/Google_Domain.mrs) |
| **Google_IP.mrs** | `ipcidr` | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_sp/Google_IP.mrs) <br> [jsDelivr CDN (推荐)](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_sp/Google_IP.mrs) |
| **ruleset.mrs** | `domain` | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_sp/ruleset.mrs) <br> [jsDelivr CDN (推荐)](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_sp/ruleset.mrs) |

<!-- RULES_END -->

## 📦 合并与去重规则 (ZH)

<!-- RULES_ZH_START -->

### 📦 自动生成的 MRS 规则集订阅链接 (ZH)

> ⏱ **最后同步时间**：`2026-10-06 16:21:31` (UTC+8)

| 文件名 | 规则类型 (Behavior) | 规则数量 | 下载链接 |
| :--- | :---: | :---: | :--- |
| **AI_Classical.txt** | `classical` | 37 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/AI_Classical.txt) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/AI_Classical.txt) |
| **AI_Domain.mrs** | `domain` | 737 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/AI_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/AI_Domain.mrs) |
| **AI_IP.mrs** | `ipcidr` | 6 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/AI_IP.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/AI_IP.mrs) |
| **Direct_CN_Domain.mrs** | `domain` | 113,571 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Direct_CN_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Direct_CN_Domain.mrs) |
| **Direct_CN_IP.mrs** | `ipcidr` | 12,535 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Direct_CN_IP.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Direct_CN_IP.mrs) |
| **NTP_Domain.mrs** | `domain` | 169 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/NTP_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/NTP_Domain.mrs) |
| **Proxy_Global_Classical.txt** | `classical` | 169 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Proxy_Global_Classical.txt) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Proxy_Global_Classical.txt) |
| **Proxy_Global_Domain.mrs** | `domain` | 29,945 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Proxy_Global_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Proxy_Global_Domain.mrs) |
| **Proxy_Global_IP.mrs** | `ipcidr` | 8,581 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Proxy_Global_IP.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Proxy_Global_IP.mrs) |
| **Reject_Ads_Classical.txt** | `classical` | 280 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Reject_Ads_Classical.txt) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Reject_Ads_Classical.txt) |
| **Reject_Ads_Domain.mrs** | `domain` | 676,394 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Reject_Ads_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Reject_Ads_Domain.mrs) |
| **Reject_Ads_IP.mrs** | `ipcidr` | 599 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/Reject_Ads_IP.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/Reject_Ads_IP.mrs) |
| **google_Classical.txt** | `classical` | 50 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/google_Classical.txt) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/google_Classical.txt) |
| **google_Domain.mrs** | `domain` | 904 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/google_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/google_Domain.mrs) |
| **google_IP.mrs** | `ipcidr` | 8,483 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/google_IP.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/google_IP.mrs) |
| **mydirect_Domain.mrs** | `domain` | 1 | [GitHub Raw](https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/mydirect_Domain.mrs) <br> [jsDelivr CDN](https://cdn.jsdelivr.net/gh/luvis1234/clash-convert@main/mrs_rules_ZH/mydirect_Domain.mrs) |

### 🧩 Mihomo 规则集引用方法

Mihomo 通过 `rule-providers` 加载远程规则集，再在 `rules` 中使用 `RULE-SET` 引用。以下示例使用 **GitHub Raw** 作为下载地址；如需使用 jsDelivr，可替换为上表对应的 CDN 链接。

> `Classical.txt` 使用 `behavior: classical` + `format: text`；`Domain.mrs` 使用 `behavior: domain` + `format: mrs`；`IP.mrs` 使用 `behavior: ipcidr` + `format: mrs`。

#### Classical.txt

适用于包含 `DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`PROCESS-NAME`、`IP-ASN` 等 Classical 规则的文本规则集。

```yaml
rule-providers:
  ai_classical:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/AI_Classical.txt"
    path: ./ruleset/AI_Classical.txt
    interval: 86400

rules:
  - RULE-SET,ai_classical,你的策略组
```

#### Domain.mrs

适用于域名类 MRS 规则集。

```yaml
rule-providers:
  ai_domain:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/AI_Domain.mrs"
    path: ./ruleset/AI_Domain.mrs
    interval: 86400

rules:
  - RULE-SET,ai_domain,你的策略组
```

#### IP.mrs

适用于 IPv4/IPv6 CIDR 类型的 MRS 规则集。

```yaml
rule-providers:
  ai_ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/luvis1234/clash-convert/main/mrs_rules_ZH/AI_IP.mrs"
    path: ./ruleset/AI_IP.mrs
    interval: 86400

rules:
  - RULE-SET,ai_ip,你的策略组,no-resolve
```

> `你的策略组` 请替换为实际代理策略组名称，例如 `DIRECT`、`REJECT`、`Proxy` 等。`IP.mrs` 示例附带 `no-resolve`，用于避免仅为 IP 规则匹配而触发 DNS 解析；可根据自己的匹配需求调整。

### ❤️ 数据来源与致谢

本项目生成的规则集基于以下优秀开源项目及规则源进行自动化整理、合并、去重与格式转换。感谢各位创作者和维护者长期提供高质量规则数据。

| 上游项目 | 用于规则组 |
| :--- | :--- |
| [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | `Reject_Ads` |
| [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | `AI` |
| [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) | `Direct_CN` |
| [bgpeer/rules](https://github.com/bgpeer/rules) | `AI`, `Direct_CN`, `google`, `NTP`, `Proxy_Global`, `Reject_Ads` |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | `AI`, `Direct_CN`, `google`, `NTP`, `Proxy_Global`, `Reject_Ads` |
| [DustinWin/domain-list-custom](https://github.com/DustinWin/domain-list-custom) | `AI` |
| [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) | `Reject_Ads` |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | `Direct_CN`, `Proxy_Global`, `Reject_Ads` |
| [luvis1234/clash-convert](https://github.com/luvis1234/clash-convert) | `mydirect`, `Reject_Ads` |
| [viewer12/OverseasAI.list](https://github.com/viewer12/OverseasAI.list) | `AI` |
| [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) | `AI` |

> 本项目仅对上游公开规则进行自动化整理、合并、去重及格式转换。  
> 原始规则的版权、许可及相关权益归各原作者及上游项目所有；使用时请同时遵循对应上游项目的许可与说明。  
> 如果这些规则对你有帮助，也请访问并支持上述原始项目。

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
