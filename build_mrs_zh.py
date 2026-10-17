import os
import re
import sys
import shutil
import datetime
import urllib.request
import urllib.error
import subprocess
import ipaddress
import traceback
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ================= 扩展性配置区 =================
RULE_GROUPS = {
    "Reject_Ads": [
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/category-ads-all.yaml",
        "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/data.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/tif.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdvertisingTest/AdvertisingTest_Classical.yaml",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.amazon-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.vivo-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.oppo-realme-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok.extended-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/urlshortener-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml",
    ],
    "Direct_CN": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaIPs/ChinaIPs_IP.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/private.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/category-bank-cn.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geoip/cn.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geoip/private.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/cn.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/tld-cn.yaml",
        "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/rule/Custom_Direct_Domain.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml",
    ],
    "Proxy_Global": [
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy_Classical.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/clash/geolocation-!cn.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/gfw.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/tld-!cn.yaml",

        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/google.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geoip/google.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml",
         ],

    "mydirect": [
        "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/mydirect.txt",
         ],
    
    "AI": [
        "https://raw.githubusercontent.com/viewer12/OverseasAI.list/main/rule/Clash/OverseasAI/OverseasAI.list",
  #      "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Ruleset/AI.list",
        "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Gemini/Gemini.yaml",
        "https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/refs/heads/main/rules/clash/global.yaml",
   #     "https://raw.githubusercontent.com/DustinWin/domain-list-custom/domains/ai.list",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/category-ai-!cn.yaml",
         ],

    "google": [
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/google.yaml",
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geoip/google.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml",
         ],

    "NTP": [
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/category-ntp.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/NTPService/NTPService.yaml",
         ],
    
    "APPLE_CN": [
        "https://raw.githubusercontent.com/bgpeer/rules/refs/heads/main/geo/geosite/apple-cn.yaml",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt",
         ],
    
}


OUTPUT_DIR = "mrs_rules_ZH"
TEMP_DIR = os.path.join(OUTPUT_DIR, "TEMP")
README_FILE = "README.md"
LOG_FILE = os.path.join(OUTPUT_DIR, "build_mrs_zh.log")

# 防呆参数
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024  # 单个规则源最大 64 MiB
VALID_PLAIN_DOMAIN_MODES = {"exact", "suffix"}

# 广告规则隔离：Reject_Ads 作为最高优先级排除基准。
# 其他所有规则组在输出前都会排除与其重叠的广告规则。
AD_EXCLUSION_GROUP = "Reject_Ads"
MAX_IP_RULES_AFTER_AD_EXCLUSION = 1_000_000


# ============================================================
# 纯文本 domain list 的默认语义
# ============================================================
#
# 纯文本：
#     example.com
#
# 本身没有 DOMAIN / DOMAIN-SUFFIX 类型信息。
#
# 当前项目中的 onlydomains/domain-list 源主要用于域名拦截，
# 因此默认将纯文本域名按 suffix 处理。
#
# 如果某个纯文本源需要精确匹配：
#     1. 源文件使用 DOMAIN,example.com
#     2. 或使用 full:example.com
#
# 可选：
#     "suffix" -> example.com 输出为 +.example.com
#     "exact"  -> example.com 输出为 example.com
#
PLAIN_DOMAIN_MODE = "exact"


# 下载超时
DOWNLOAD_TIMEOUT = 300


class TeeStream:
    """把 stdout/stderr 同时写到终端和 UTF-8 日志文件。"""
    def __init__(self, terminal, log_handle, lock):
        self.terminal = terminal
        self.log_handle = log_handle
        self.lock = lock

    def write(self, message):
        if not message:
            return 0
        with self.lock:
            self.terminal.write(message)
            self.terminal.flush()
            self.log_handle.write(message)
            self.log_handle.flush()
        return len(message)

    def flush(self):
        with self.lock:
            self.terminal.flush()
            self.log_handle.flush()

    def isatty(self):
        return getattr(self.terminal, "isatty", lambda: False)()


def setup_logging():
    """初始化执行日志；每次运行覆盖旧日志，确保看到的是本次完整结果。"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    log_handle = open(LOG_FILE, "w", encoding="utf-8", newline="\n", buffering=1)
    lock = threading.RLock()
    sys.stdout = TeeStream(sys.__stdout__, log_handle, lock)
    sys.stderr = TeeStream(sys.__stderr__, log_handle, lock)
    return log_handle


def setup_dirs():
    """初始化输出目录，并清理本次构建使用的临时目录。"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    # TEMP 只保存中间产物，不应跨构建保留，避免旧临时文件干扰排查。
    if os.path.isdir(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)



def get_mihomo_version(mihomo_path: str) -> str:
    """读取 mihomo 版本信息；失败时返回可读占位信息。"""
    try:
        result = subprocess.run(
            [mihomo_path, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        text = (result.stdout or result.stderr or "").strip()
        return text or "unknown"
    except Exception as e:
        return f"unknown ({e})"


def cleanup_group_outputs(group_name: str, keep=None):
    """删除某规则组不再属于本次构建结果的旧输出。

    keep 为需要保留的文件名集合；默认删除该组全部标准输出。
    """
    keep = set(keep or ())
    candidates = (
        f"{group_name}_Domain.mrs",
        f"{group_name}_IP.mrs",
        f"{group_name}_Classical.txt",
    )
    for filename in candidates:
        if filename in keep:
            continue
        path = os.path.join(OUTPUT_DIR, filename)
        if os.path.isfile(path):
            try:
                os.remove(path)
                print(f"  🧹 已删除旧输出: {path}")
            except OSError as e:
                print(f"  ⚠️ 删除旧输出失败 {path}: {e}")


def validate_readme_markers(readme_content: str):
    """确保 README 自动生成区域标记唯一且成对，避免误覆盖人工内容。"""
    start = "<!-- RULES_ZH_START -->"
    end = "<!-- RULES_ZH_END -->"
    start_count = readme_content.count(start)
    end_count = readme_content.count(end)

    if start_count == 0 and end_count == 0:
        return False
    if start_count != 1 or end_count != 1:
        raise RuntimeError(
            "README 自动区域标记异常："
            f"RULES_ZH_START={start_count}, RULES_ZH_END={end_count}。"
            "请确保两个标记各只有一个。"
        )
    if readme_content.find(start) > readme_content.find(end):
        raise RuntimeError("README 自动区域标记顺序错误：START 位于 END 之后。")
    return True


def validate_config():
    """启动前检查配置，尽早暴露常见误配置。"""
    errors = []
    warnings = []

    if PLAIN_DOMAIN_MODE not in VALID_PLAIN_DOMAIN_MODES:
        errors.append(
            f"PLAIN_DOMAIN_MODE={PLAIN_DOMAIN_MODE!r} 非法，"
            f"只能是 {sorted(VALID_PLAIN_DOMAIN_MODES)}"
        )

    if not RULE_GROUPS:
        errors.append("RULE_GROUPS 为空，没有任何规则组可处理。")

    if AD_EXCLUSION_GROUP not in RULE_GROUPS:
        errors.append(
            f"广告排除基准规则组 {AD_EXCLUSION_GROUP!r} 不存在；"
            "无法保证其他规则组排除广告规则。"
        )

    seen_global = {}
    for group, urls in RULE_GROUPS.items():
        if not isinstance(group, str) or not group.strip():
            errors.append(f"发现非法规则组名称: {group!r}")
        if not urls:
            warnings.append(f"规则组 {group!r} 没有配置任何源。")
            continue

        seen_local = set()
        for url in urls:
            if not isinstance(url, str) or not url.strip():
                errors.append(f"规则组 {group!r} 存在空/非字符串 URL: {url!r}")
                continue
            clean = url.strip()
            if not re.match(r"^https?://", clean, re.IGNORECASE):
                errors.append(f"规则组 {group!r} URL 不是 HTTP(S): {clean}")
            if clean in seen_local:
                warnings.append(f"规则组 {group!r} 存在重复 URL: {clean}")
            seen_local.add(clean)
            if clean in seen_global and seen_global[clean] != group:
                warnings.append(
                    f"URL 同时出现在 {seen_global[clean]!r} 和 {group!r}: {clean}"
                )
            else:
                seen_global[clean] = group

            if re.search(r"github\.com/[^/]+/[^/]+/blob/", clean, re.IGNORECASE):
                warnings.append(f"检测到 GitHub blob URL，将自动转换为 Raw: {clean}")

    mihomo = shutil.which("mihomo")
    if not mihomo:
        errors.append("未找到 mihomo 命令，请安装并加入 PATH。")
    else:
        print(f"🔧 mihomo: {mihomo}")
        print(f"🔧 Mihomo 版本: {get_mihomo_version(mihomo)}")

    for msg in warnings:
        print(f"⚠️ 配置提示: {msg}")

    if errors:
        for msg in errors:
            print(f"❌ 配置错误: {msg}")
        raise RuntimeError(f"启动检查失败，共 {len(errors)} 项错误。")


def content_has_html_residue(content: str) -> bool:
    """检查即使 Content-Type 错误时仍可能漏网的明显 HTML/网页片段。"""
    sample = content[:200000].lower()
    markers = (
        "<!doctype html", "<html", "</html>", "<head", "</head>",
        "<body", "</body>", "<script", "</script>", "<style", "</style>",
        "data-view-component=", "github-code-view", "react-app.reactroot",
    )
    return any(marker in sample for marker in markers)


def validate_parsed_result(url: str, content: str, parsed):
    """解析结果健全性检查，防止网页/错误页/空文件继续污染输出。"""
    suffixes, exacts, ipcidrs, others, unknown_types = parsed
    total = len(suffixes) + len(exacts) + len(ipcidrs) + len(others)

    if not content.strip():
        raise ValueError(f"规则源内容为空: {url}")
    if content_has_html_residue(content):
        raise ValueError(f"规则源疑似仍包含 HTML/网页内容，已拒绝: {url}")
    if total == 0:
        raise ValueError(f"规则源未解析出任何有效规则: {url}")

    # Classical 中若残留明显 HTML 标签，说明输入格式异常。
    suspicious = [
        rule for rule in others
        if re.search(r"</?[a-z][^>]*>|&(?:nbsp|copy|quot|amp);", rule, re.IGNORECASE)
    ]
    if suspicious:
        preview = " | ".join(sorted(suspicious)[:3])
        raise ValueError(
            f"Classical 结果中检测到疑似网页残片 ({len(suspicious)} 条): {preview}"
        )

    return parsed

def normalize_ip_cidr(val: str):
    """规范化 IPv4/IPv6 地址或 CIDR；纯 IP 自动补 /32 或 /128。"""
    val = val.strip()
    try:
        if "/" in val:
            return ipaddress.ip_network(val, strict=False)
        return ipaddress.ip_network(val + ("/128" if ":" in val else "/32"))
    except ValueError:
        return None


def is_ip_like(val: str) -> bool:
    """判断字符串是否明显像 IP/IP-CIDR，但不负责验证合法性。"""
    val = val.strip()
    return bool(
        re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,3})?", val)
        or (":" in val and re.fullmatch(r"[0-9a-fA-F:.]+(?:/\d{1,3})?", val))
    )


def is_ip_or_cidr(val: str) -> bool:
    return normalize_ip_cidr(val) is not None


def canonical_ip_cidr(val: str):
    network = normalize_ip_cidr(val)
    return str(network) if network is not None else None


def deduplicate_ip_networks(networks):
    """全局 IP/CIDR 规范化、去重和合并；IPv4/IPv6 分开 collapse。"""
    ipv4, ipv6 = [], []
    for item in networks:
        net = item if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else normalize_ip_cidr(str(item))
        if net is None:
            continue
        (ipv4 if net.version == 4 else ipv6).append(net)
    merged = list(ipaddress.collapse_addresses(ipv4)) + list(ipaddress.collapse_addresses(ipv6))
    return [str(n) for n in sorted(merged, key=lambda n: (n.version, int(n.network_address), n.prefixlen))]


def normalize_domain(val: str) -> str:
    """
    标准化域名。

    处理：
      - 首尾空白
      - 小写
      - 最后的 .
      - 开头的 .

    例如：

        Example.COM.      -> example.com
        .Example.COM      -> example.com
        example.com       -> example.com
    """

    val = val.strip().lower().rstrip(".")

    return val.lstrip(".")


def parse_rules_from_content(content: str):
    """解析 Clash/Mihomo 规则，并严格分离 Domain、目标 IP 和 Classical。

    返回值额外包含未知 Classical 规则类型统计，用于日志告警；
    未知类型仍保留到 Classical，避免未来 Mihomo 新规则被静默丢弃。
    """
    suffixes, exacts, ipcidrs, others = set(), set(), set(), set()
    unknown_types = {}

    def strip_safe_inline_comment(value: str) -> str:
        """仅对确定为普通值的字段剥离空白后的 # 注释，避免影响 regex 等规则。"""
        return re.split(r"\s+#", value, maxsplit=1)[0].strip()

    def add_domain(target, value, rule_type):
        value=value.strip()
        cidr=canonical_ip_cidr(value)
        if cidr is not None:
            ipcidrs.add(cidr); return
        if is_ip_like(value):
            others.add(f"{rule_type},{value}"); return
        domain=normalize_domain(value)
        if domain: target.add(domain)

    for raw in content.splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or line == 'payload:': continue
        if line.startswith('-'): line=line[1:].strip()
        if not line or line.startswith('#'): continue
        if (line.startswith("'") and line.endswith("'")) or (line.startswith('"') and line.endswith('"')):
            line=line[1:-1].strip()
        if not line: continue
        rule=line.lower().strip()

        if ',' in rule:
            parts=[p.strip() for p in rule.split(',')]
            typ,val=parts[0],parts[1] if len(parts)>1 else ''
            if typ in ('rule-set','sub-rule'): continue
            if typ=='domain-suffix': add_domain(suffixes,strip_safe_inline_comment(val),'DOMAIN-SUFFIX')
            elif typ=='domain': add_domain(exacts,strip_safe_inline_comment(val),'DOMAIN')
            elif typ in ('ip-cidr','ip-cidr6'):
                val = strip_safe_inline_comment(val)
                cidr=canonical_ip_cidr(val)
                if cidr: ipcidrs.add(cidr)
                elif val: others.add(rule)
            elif typ=='src-ip-cidr':
                val = strip_safe_inline_comment(val)
                if val: others.add(','.join([typ, val] + parts[2:]))
            elif typ=='domain-keyword':
                val = strip_safe_inline_comment(val)
                if val: others.add(','.join([typ, val] + parts[2:]))
            elif typ=='domain-regex':
                if val: others.add(rule)
            else:
                if typ:
                    unknown_types[typ] = unknown_types.get(typ, 0) + 1
                others.add(','.join(parts))
            continue

        if rule.startswith('full:'): add_domain(exacts,rule[5:],'DOMAIN')
        elif rule.startswith('+.'): add_domain(suffixes,rule[2:],'DOMAIN-SUFFIX')
        elif rule.startswith('keyword:') or rule.startswith('regexp:'): others.add(rule)
        elif is_ip_or_cidr(rule): ipcidrs.add(canonical_ip_cidr(rule))
        elif is_ip_like(rule): others.add(rule)
        elif rule.startswith('.'): add_domain(suffixes,rule,'DOMAIN-SUFFIX')
        else:
            domain=normalize_domain(rule)
            if not domain: continue
            if PLAIN_DOMAIN_MODE=='suffix': suffixes.add(domain)
            else: exacts.add(domain)

    return suffixes,exacts,ipcidrs,others,unknown_types


def _domain_parents(domain: str):
    if '*' in domain: return []
    parts=domain.split('.')
    if len(parts)<2: return []
    return ['.'.join(parts[i:]) for i in range(1,len(parts)-1) if '.'.join(parts[i:]).count('.')>=1]


def deduplicate_domains(suffixes: set, exacts: set):
    optimized_suffixes=set()
    for domain in sorted(suffixes,key=lambda x:(x.count('.'),x)):
        if not any(p in optimized_suffixes for p in _domain_parents(domain)):
            optimized_suffixes.add(domain)
    optimized_exacts=set()
    for domain in exacts:
        if domain in optimized_suffixes or any(p in optimized_suffixes for p in _domain_parents(domain)):
            continue
        optimized_exacts.add(domain)
    return optimized_suffixes,optimized_exacts


def _domain_covered_by_suffix_set(domain: str, suffixes: set) -> bool:
    """判断域名是否被广告 DOMAIN-SUFFIX 集合覆盖。"""
    domain = normalize_domain(domain)
    if not domain or '*' in domain:
        return domain in suffixes
    if domain in suffixes:
        return True
    return any(parent in suffixes for parent in _domain_parents(domain))


def extract_ad_domain_keywords(ad_others: set) -> set:
    """从 Reject_Ads Classical 规则中提取 DOMAIN-KEYWORD 的字面关键词。

    这些关键词只用于 Reject_Ads 自身的 Domain/Domain-Suffix 冗余精简。
    不使用 DOMAIN-KEYWORD 对其他规则组的域名做子串排除。
    """
    keywords = set()
    for rule in ad_others:
        if not rule.startswith("domain-keyword,"):
            continue
        parts = rule.split(",", 2)
        if len(parts) < 2:
            continue
        keyword = parts[1].strip().lower()
        if keyword:
            keywords.add(keyword)
    return keywords


def compile_domain_keyword_pattern(keywords: set):
    """把 DOMAIN-KEYWORD 集合编译为字面子串匹配正则；空集合返回 None。"""
    if not keywords:
        return None
    # 长关键词优先仅为日志/调试时更直观；所有关键词均 re.escape，按字面匹配。
    alternatives = sorted((re.escape(k) for k in keywords), key=len, reverse=True)
    return re.compile("|".join(alternatives), re.IGNORECASE)


def exclude_ad_domains(
    suffixes: set,
    exacts: set,
    ad_suffixes: set,
    ad_exacts: set,
):
    """从普通规则组中排除与 Reject_Ads Domain 规则直接重叠的域名。

    规则：
      - 广告 suffix 覆盖相同/子级 suffix，也覆盖其下 exact；
      - 广告 exact 只删除同名 exact，不会扩大为 suffix；
      - DOMAIN-KEYWORD 不参与其他规则组域名的子串排除。
    """
    kept_suffixes = set()
    kept_exacts = set()
    suffix_removed = 0
    exact_removed = 0

    for domain in suffixes:
        if _domain_covered_by_suffix_set(domain, ad_suffixes):
            suffix_removed += 1
            continue
        kept_suffixes.add(domain)

    for domain in exacts:
        if domain in ad_exacts or _domain_covered_by_suffix_set(domain, ad_suffixes):
            exact_removed += 1
            continue
        kept_exacts.add(domain)

    stats = {
        "suffix_removed": suffix_removed,
        "exact_removed": exact_removed,
    }
    return kept_suffixes, kept_exacts, stats


def prune_ad_domains_by_keywords(
    suffixes: set,
    exacts: set,
    ad_keywords: set,
):
    """用 Reject_Ads 自身 DOMAIN-KEYWORD 精简其 Domain 规则。

    该步骤只作用于 Reject_Ads 自身，且必须发生在：
      1. 完整 Reject_Ads 基准已经用于排除其他规则组的重叠规则之后；
      2. Reject_Ads_Domain.mrs 生成之前。

    例如 DOMAIN-KEYWORD,abc 已经能够覆盖 zxabc.com / zx-abc.com，
    则这些 DOMAIN / DOMAIN-SUFFIX 规则可从 Reject_Ads_Domain.mrs 中移除，
    但 DOMAIN-KEYWORD,abc 本身仍保留在 Reject_Ads_Classical.txt 中。
    """
    keyword_pattern = compile_domain_keyword_pattern(set(ad_keywords or ()))
    if keyword_pattern is None:
        return set(suffixes), set(exacts), {
            "suffix_removed": 0,
            "exact_removed": 0,
            "total_removed": 0,
        }

    kept_suffixes = set()
    kept_exacts = set()
    suffix_removed = 0
    exact_removed = 0

    for domain in suffixes:
        if keyword_pattern.search(normalize_domain(domain)):
            suffix_removed += 1
            continue
        kept_suffixes.add(domain)

    for domain in exacts:
        if keyword_pattern.search(normalize_domain(domain)):
            exact_removed += 1
            continue
        kept_exacts.add(domain)

    return kept_suffixes, kept_exacts, {
        "suffix_removed": suffix_removed,
        "exact_removed": exact_removed,
        "total_removed": suffix_removed + exact_removed,
    }


def subtract_ad_ip_networks(networks, ad_networks):
    """从普通 IP/CIDR 规则中精确扣除 Reject_Ads 的 IP 网段。

    对部分重叠不粗暴删除整个正常网段，而是用 summarize_address_range
    将剩余地址重新汇总为 CIDR，因此可以真正排除广告 IP，同时保留非广告地址。
    """
    src = [normalize_ip_cidr(item) for item in networks]
    src = [net for net in src if net is not None]
    exc = [normalize_ip_cidr(item) for item in ad_networks]
    exc = [net for net in exc if net is not None]

    by_version_src = {4: [], 6: []}
    by_version_exc = {4: [], 6: []}
    for net in src:
        by_version_src[net.version].append(net)
    for net in exc:
        by_version_exc[net.version].append(net)

    output = []
    fully_removed = 0
    partially_split = 0
    removed_addresses = 0

    for version in (4, 6):
        sources = sorted(
            ipaddress.collapse_addresses(by_version_src[version]),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        exclusions = sorted(
            ipaddress.collapse_addresses(by_version_exc[version]),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        addr_cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        ex_index = 0

        for source in sources:
            source_start = int(source.network_address)
            source_end = int(source.broadcast_address)

            while (
                ex_index < len(exclusions)
                and int(exclusions[ex_index].broadcast_address) < source_start
            ):
                ex_index += 1

            cursor = source_start
            had_overlap = False
            kept_ranges = []
            k = ex_index

            while k < len(exclusions):
                exclusion = exclusions[k]
                ex_start = int(exclusion.network_address)
                ex_end = int(exclusion.broadcast_address)
                if ex_start > source_end:
                    break
                if ex_end < source_start:
                    k += 1
                    continue

                overlap_start = max(cursor, ex_start, source_start)
                overlap_end = min(source_end, ex_end)
                if overlap_start <= overlap_end:
                    had_overlap = True
                    if cursor < overlap_start:
                        kept_ranges.append((cursor, overlap_start - 1))
                    removed_addresses += overlap_end - overlap_start + 1
                    cursor = max(cursor, overlap_end + 1)
                    if cursor > source_end:
                        break
                k += 1

            if not had_overlap:
                output.append(source)
                continue

            if cursor <= source_end:
                kept_ranges.append((cursor, source_end))

            if not kept_ranges:
                fully_removed += 1
                continue

            partially_split += 1
            for start, end in kept_ranges:
                output.extend(
                    ipaddress.summarize_address_range(addr_cls(start), addr_cls(end))
                )
                if len(output) > MAX_IP_RULES_AFTER_AD_EXCLUSION:
                    raise RuntimeError(
                        "广告 IP 排除后 CIDR 数量异常膨胀，超过安全上限 "
                        f"{MAX_IP_RULES_AFTER_AD_EXCLUSION:,}；请检查 Reject_Ads IP 源。"
                    )

    output = sorted(
        ipaddress.collapse_addresses(output),
        key=lambda n: (n.version, int(n.network_address), n.prefixlen),
    )
    stats = {
        "input_networks": len(src),
        "output_networks": len(output),
        "fully_removed": fully_removed,
        "partially_split": partially_split,
        "removed_addresses": removed_addresses,
    }
    return [str(net) for net in output], stats


def exclude_ad_classical(others: set, ad_others: set):
    """Classical 规则按解析后的完整规范化文本精确排除。"""
    kept = others.difference(ad_others)
    return kept, len(others) - len(kept)


def convert_to_mrs(
    src_path: str,
    format_type: str,
    behavior_type: str,
    output_name: str,
) -> bool:
    """
    调用：

        mihomo convert-ruleset

    例如：

        mihomo convert-ruleset \
            domain \
            text \
            input.txt \
            output.mrs
    """

    out_file = os.path.join(
        OUTPUT_DIR,
        f"{output_name}.mrs",
    )

    # --------------------------------------------------------
    # 删除旧文件
    # --------------------------------------------------------
    if os.path.exists(out_file):

        try:
            os.remove(out_file)

        except OSError:
            pass

    cmd = [
        "mihomo",
        "convert-ruleset",
        behavior_type,
        format_type,
        src_path,
        out_file,
    ]

    try:

        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())

        if not os.path.isfile(out_file):
            print(f"❌ 转换命令返回成功，但输出文件不存在: {out_file}")
            return False
        if os.path.getsize(out_file) <= 0:
            print(f"❌ 转换命令返回成功，但输出文件为空: {out_file}")
            return False

        print(f"  ✅ MRS 已生成: {out_file} ({os.path.getsize(out_file):,} bytes)")
        return True

    except subprocess.CalledProcessError as e:

        print(
            f"❌ 转换失败: {output_name}"
        )

        if e.stdout:
            print(e.stdout.strip())

        if e.stderr:
            print(e.stderr.strip())

        return False

    except FileNotFoundError:

        print(
            "❌ 未找到 mihomo 命令，"
            "请确认 mihomo 已安装并在 PATH 中。"
        )

        return False


def extract_github_repo_from_url(url: str):
    """
    从规则源 URL 自动提取 GitHub owner/repo。

    支持：
      - https://raw.githubusercontent.com/owner/repo/...
      - https://github.com/owner/repo/...
      - https://cdn.jsdelivr.net/gh/owner/repo@ref/...
      - https://fastly.jsdelivr.net/gh/owner/repo@ref/...

    返回 (owner, repo)；无法识别时返回 None。
    """
    url = (url or "").strip()
    patterns = (
        r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)(?:/|$)",
        r"^https?://github\.com/([^/]+)/([^/]+)(?:/|$)",
        r"^https?://(?:cdn|fastly)\.jsdelivr\.net/gh/([^/]+)/([^/@]+)(?:@[^/]+)?(?:/|$)",
    )
    for pattern in patterns:
        match = re.match(pattern, url, flags=re.IGNORECASE)
        if match:
            owner = match.group(1).strip()
            repo = match.group(2).strip()
            if repo.endswith(".git"):
                repo = repo[:-4]
            if owner and repo:
                return owner, repo
    return None


def collect_source_credits():
    """
    从 RULE_GROUPS 中自动汇总上游 GitHub 项目，按 owner/repo 去重。

    返回：
        [(display_name, repo_url, groups), ...]
    """
    credits = {}

    for group_name, urls in RULE_GROUPS.items():
        for url in urls:
            parsed = extract_github_repo_from_url(url)
            if not parsed:
                continue

            owner, repo = parsed
            key = (owner.lower(), repo.lower())
            item = credits.setdefault(
                key,
                {
                    "owner": owner,
                    "repo": repo,
                    "groups": set(),
                },
            )
            item["groups"].add(group_name)

    result = []
    for item in credits.values():
        owner = item["owner"]
        repo = item["repo"]
        display_name = f"{owner}/{repo}"
        repo_url = f"https://github.com/{owner}/{repo}"
        groups = sorted(item["groups"], key=str.lower)
        result.append((display_name, repo_url, groups))

    return sorted(result, key=lambda x: x[0].lower())


def update_readme(success_files):
    """
    更新 README 中的自动生成规则订阅表。
    """

    if not success_files:
        return

    repo = os.environ.get(
        "GITHUB_REPOSITORY",
        "your-username/your-repo",
    )

    branch = "main"

    tz_utc_8 = datetime.timezone(
        datetime.timedelta(hours=8)
    )

    now_str = datetime.datetime.now(
        tz_utc_8
    ).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    md_content = (
        "\n### 📦 自动生成的 MRS 规则集订阅链接 (ZH)\n\n"
        f"> ⏱ **最后同步时间**：`{now_str}` (UTC+8)\n\n"
        f"> 🛡️ **广告规则隔离**：`{AD_EXCLUSION_GROUP}` 作为最高优先级基准；"
        "其他所有规则组会先排除与其直接重叠的 Domain、IP/CIDR 和 Classical 规则。"
        f"随后仅在 `{AD_EXCLUSION_GROUP}` 自身内部，使用广告 `DOMAIN-KEYWORD` 按 Mihomo 子串语义"
        "精简已被关键词覆盖的 Domain/Domain-Suffix 规则，再生成最终规则集。\n\n"
        "| 文件名 | 规则类型 (Behavior) | 规则数量 | 下载链接 |\n"
        "| :--- | :---: | :---: | :--- |\n"
    )

    for (
        filename,
        behavior,
        count,
    ) in sorted(
        success_files,
        key=lambda x: x[0],
    ):

        raw_url = (
            f"https://raw.githubusercontent.com/"
            f"{repo}/{branch}/{OUTPUT_DIR}/{filename}"
        )

        cdn_url = (
            f"https://cdn.jsdelivr.net/gh/"
            f"{repo}@{branch}/{OUTPUT_DIR}/{filename}"
        )

        links = (
            f"[GitHub Raw]({raw_url}) "
            f"<br> "
            f"[jsDelivr CDN]({cdn_url})"
        )

        md_content += (
            f"| **{filename}** | "
            f"`{behavior}` | "
            f"{count:,} | "
            f"{links} |\n"
        )

    # --------------------------------------------------------
    # Mihomo 三类规则集引用方法
    # --------------------------------------------------------
    # 根据本次实际生成结果各挑一个可用示例，确保 README 中的
    # 文件名和 URL 与仓库当前产物保持一致。
    examples = {}
    for filename, behavior, _count in sorted(success_files, key=lambda x: x[0]):
        if behavior in ("classical", "domain", "ipcidr") and behavior not in examples:
            examples[behavior] = filename

    md_content += (
        "\n### 🧩 Mihomo 规则集引用方法\n\n"
        "Mihomo 通过 `rule-providers` 加载远程规则集，再在 `rules` 中使用 "
        "`RULE-SET` 引用。以下示例使用 **GitHub Raw** 作为下载地址；"
        "如需使用 jsDelivr，可替换为上表对应的 CDN 链接。\n\n"
        "> `Classical.txt` 使用 `behavior: classical` + `format: text`；"
        "`Domain.mrs` 使用 `behavior: domain` + `format: mrs`；"
        "`IP.mrs` 使用 `behavior: ipcidr` + `format: mrs`。\n\n"
    )

    def _provider_url(filename):
        return (
            f"https://raw.githubusercontent.com/"
            f"{repo}/{branch}/{OUTPUT_DIR}/{filename}"
        )

    if "classical" in examples:
        filename = examples["classical"]
        provider_name = re.sub(r"[^a-zA-Z0-9_]+", "_", Path(filename).stem).strip("_").lower()
        md_content += (
            "#### Classical.txt\n\n"
            "适用于包含 `DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`PROCESS-NAME`、"
            "`IP-ASN` 等 Classical 规则的文本规则集。\n\n"
            "```yaml\n"
            "rule-providers:\n"
            f"  {provider_name}:\n"
            "    type: http\n"
            "    behavior: classical\n"
            "    format: text\n"
            f"    url: \"{_provider_url(filename)}\"\n"
            f"    path: ./ruleset/{filename}\n"
            "    interval: 86400\n\n"
            "rules:\n"
            f"  - RULE-SET,{provider_name},你的策略组\n"
            "```\n\n"
        )

    if "domain" in examples:
        filename = examples["domain"]
        provider_name = re.sub(r"[^a-zA-Z0-9_]+", "_", Path(filename).stem).strip("_").lower()
        md_content += (
            "#### Domain.mrs\n\n"
            "适用于域名类 MRS 规则集。\n\n"
            "```yaml\n"
            "rule-providers:\n"
            f"  {provider_name}:\n"
            "    type: http\n"
            "    behavior: domain\n"
            "    format: mrs\n"
            f"    url: \"{_provider_url(filename)}\"\n"
            f"    path: ./ruleset/{filename}\n"
            "    interval: 86400\n\n"
            "rules:\n"
            f"  - RULE-SET,{provider_name},你的策略组\n"
            "```\n\n"
        )

    if "ipcidr" in examples:
        filename = examples["ipcidr"]
        provider_name = re.sub(r"[^a-zA-Z0-9_]+", "_", Path(filename).stem).strip("_").lower()
        md_content += (
            "#### IP.mrs\n\n"
            "适用于 IPv4/IPv6 CIDR 类型的 MRS 规则集。\n\n"
            "```yaml\n"
            "rule-providers:\n"
            f"  {provider_name}:\n"
            "    type: http\n"
            "    behavior: ipcidr\n"
            "    format: mrs\n"
            f"    url: \"{_provider_url(filename)}\"\n"
            f"    path: ./ruleset/{filename}\n"
            "    interval: 86400\n\n"
            "rules:\n"
            f"  - RULE-SET,{provider_name},你的策略组,no-resolve\n"
            "```\n\n"
        )

    md_content += (
        "> `你的策略组` 请替换为实际代理策略组名称，例如 `DIRECT`、`REJECT`、"
        "`Proxy` 等。`IP.mrs` 示例附带 `no-resolve`，用于避免仅为 IP 规则匹配而触发 DNS 解析；"
        "可根据自己的匹配需求调整。\n"
    )

    # --------------------------------------------------------
    # 自动从 RULE_GROUPS 的源链接生成上游项目致谢
    # --------------------------------------------------------
    source_credits = collect_source_credits()

    if source_credits:
        md_content += (
            "\n### ❤️ 数据来源与致谢\n\n"
            "本项目生成的规则集基于以下优秀开源项目及规则源进行自动化整理、"
            "合并、去重与格式转换。感谢各位创作者和维护者长期提供高质量规则数据。\n\n"
            "| 上游项目 | 用于规则组 |\n"
            "| :--- | :--- |\n"
        )

        for display_name, repo_url, groups in source_credits:
            group_text = ", ".join(f"`{group}`" for group in groups)
            md_content += (
                f"| [{display_name}]({repo_url}) | {group_text} |\n"
            )

        md_content += (
            "\n> 本项目仅对上游公开规则进行自动化整理、合并、去重及格式转换。  \n"
            "> 原始规则的版权、许可及相关权益归各原作者及上游项目所有；"
            "使用时请同时遵循对应上游项目的许可与说明。  \n"
            "> 如果这些规则对你有帮助，也请访问并支持上述原始项目。\n"
        )

    # --------------------------------------------------------
    # README 不存在时创建基础结构
    # --------------------------------------------------------
    if not os.path.exists(README_FILE):

        with open(
            README_FILE,
            "w",
            encoding="utf-8",
        ) as f:

            f.write(
                "# Mihomo Ruleset Builder\n\n"
                "自动聚合多个公开规则源，对域名、IP/CIDR 和 Classical 规则进行"
                "解析、合并、去重与格式转换，并生成适用于 Mihomo 的规则集。\n\n"
                "## ✨ 项目特点\n\n"
                "- 自动下载并合并多个上游规则源\n"
                "- 自动区分 Domain、IP/CIDR、Classical 规则\n"
                "- 自动域名去重和 IP/CIDR 合并\n"
                "- 自动生成 Mihomo `.mrs` 规则集\n"
                "- 自动检测 GitHub HTML 页面污染\n"
                "- 自动生成构建日志\n"
                f"- 自动以 `{AD_EXCLUSION_GROUP}` 为基准排除其他规则组中的广告规则\n"
                "- 自动生成 README 使用示例和上游致谢\n\n"
                "## 📦 基础规则\n\n"
                "<!-- RULES_START -->\n"
                "<!-- RULES_END -->\n\n"
                "## 📦 合并与去重规则 (ZH)\n\n"
                "<!-- RULES_ZH_START -->\n"
                "<!-- RULES_ZH_END -->\n\n"
                "## 🔄 更新与缓存说明\n\n"
                "本项目规则由自动化任务定期生成。GitHub Raw 为推荐的权威下载地址；"
                "jsDelivr CDN 可能由于缓存机制短时间返回旧版本，请优先使用 GitHub Raw 验证最新内容。\n\n"
                "## ⚠️ 免责声明\n\n"
                "本项目仅对公开规则源进行自动化下载、解析、合并、去重及格式转换。"
                "规则内容及可用性主要取决于上游规则源，使用后可能出现误拦截、漏匹配或网络异常，"
                "请根据实际环境自行调整。上游规则的版权、许可及相关权益归对应原作者及项目所有，"
                "使用时请遵守对应上游项目的许可与说明。\n\n"
                "## 🐛 问题反馈\n\n"
                "欢迎通过 GitHub Issues 反馈规则源失效、解析异常、MRS 转换失败、规则分类错误或 README 自动生成异常。"
                "提交问题时建议附上规则组、源 URL 和 `mrs_rules_ZH/build_mrs_zh.log`。\n\n"
                "## 🤝 参与贡献\n\n"
                "欢迎提交 Issue 或 Pull Request。详细要求请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。\n\n"
                "## 🔐 安全问题\n\n"
                "请按照 [SECURITY.md](SECURITY.md) 中的说明报告安全问题。\n\n"
                "## 📄 License\n\n"
                "本项目代码许可方式请参阅 [LICENSE](LICENSE)。上游规则数据仍遵循各自项目的许可要求。\n"
            )

    # --------------------------------------------------------
    # 读取 README
    # --------------------------------------------------------
    with open(
        README_FILE,
        "r",
        encoding="utf-8",
    ) as f:

        readme_content = f.read()

    # --------------------------------------------------------
    # 替换自动生成区域
    # --------------------------------------------------------
    has_markers = validate_readme_markers(readme_content)
    pattern = re.compile(
        r"<!-- RULES_ZH_START -->.*?<!-- RULES_ZH_END -->",
        re.DOTALL,
    )

    replacement = (
        "<!-- RULES_ZH_START -->\n"
        f"{md_content}\n"
        "<!-- RULES_ZH_END -->"
    )

    if has_markers and pattern.search(readme_content):

        new_content = pattern.sub(
            replacement,
            readme_content,
        )

    else:

        new_content = (
            readme_content
            + "\n\n"
            + replacement
        )

    # --------------------------------------------------------
    # 写回 README
    # --------------------------------------------------------
    with open(
        README_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(new_content)


def normalize_source_url(url: str) -> str:
    """
    规范化规则源 URL。

    GitHub 的 /blob/ 地址返回的是 HTML 文件浏览页面，不是原始文件。
    自动转换为 raw.githubusercontent.com，避免 HTML 被误解析成 Classical 规则。
    """
    m = re.match(
        r"^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$",
        url.strip(),
        flags=re.IGNORECASE,
    )
    if m:
        owner, repo, ref, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    return url.strip()


def looks_like_html(data: bytes, content_type: str = "") -> bool:
    """保守判断响应是否为 HTML 页面。"""
    ct = (content_type or "").lower()
    if "text/html" in ct or "application/xhtml+xml" in ct:
        return True

    head = data[:4096].lstrip().lower()
    html_markers = (
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<body",
        b"<script",
        b"<meta ",
    )
    return any(head.startswith(marker) for marker in html_markers)


def _declared_charset(content_type: str) -> str | None:
    """提取 HTTP Content-Type 中声明的 charset，仅作为弱提示使用。"""
    m = re.search(r"charset=([\w.\-]+)", content_type or "", re.IGNORECASE)
    if not m:
        return None
    return m.group(1).strip('"\\\'').lower()


def _looks_like_mojibake(text: str) -> bool:
    """
    检测常见 UTF-8 被错误按 latin1/cp1252 解码后的乱码特征。

    这里只拦截高置信度特征，避免误伤正常规则内容。
    """
    sample = text[:20000]
    markers = (
        "Ã", "Â", "â€", "â€™", "â€œ", "â€", "â€“", "â€”",
        "ä¸", "ä¹", "äº", "å®", "æ–", "çš", "é€", "ï»¿",
        "�",
    )
    hits = sum(sample.count(m) for m in markers)
    # 规则文件以 ASCII 为主，出现多个此类组合通常已经足够可疑。
    return hits >= 3


def decode_text_bytes(data: bytes, content_type: str = "") -> str:
    """
    安全解码规则文本。

    重要：不盲信 GitHub 加速/CDN返回的 charset。
    一些代理会把实际 UTF-8 错误标成 ISO-8859-1、GBK 等；如果优先
    使用该 charset，decode() 可能成功但产生 mojibake（假成功）。

    顺序：
      1. UTF-8 BOM / UTF-8（严格）
      2. GB18030（兼容常见中文源）
      3. HTTP 声明 charset（仅兜底）
    """
    declared = _declared_charset(content_type)

    candidates = ["utf-8-sig", "utf-8", "gb18030"]
    if declared and declared not in candidates:
        candidates.append(declared)

    tried = set()
    mojibake_candidates = []

    for enc in candidates:
        enc_key = enc.lower()
        if enc_key in tried:
            continue
        tried.add(enc_key)
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

        if _looks_like_mojibake(text):
            mojibake_candidates.append(enc)
            continue

        if declared and enc_key != declared.lower():
            # 只在声明值明显可疑时记录，方便从执行日志定位加速节点问题。
            if declared.lower() not in ("utf-8", "utf8", "utf-8-sig"):
                print(
                    f"  ⚠️ HTTP 声明 charset={declared}，"
                    f"但内容按 {enc} 严格解码正常；已忽略可疑 charset"
                )
        return text

    extra = ""
    if mojibake_candidates:
        extra = f"；以下编码虽可解码但疑似产生乱码: {', '.join(mojibake_candidates)}"
    raise UnicodeError(
        "无法可靠解码规则源：UTF-8/GB18030/HTTP charset 均失败"
        + extra
    )


def download_text(url: str) -> str:
    """下载规则源、拒绝 HTML 页面，并安全解码。"""
    original_url = url
    url = normalize_source_url(url)
    if url != original_url:
        print(f"  ↪ GitHub blob 自动转换为 Raw: {url}")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 "
                "(Mihomo-MRS-Builder)"
            ),
            "Accept": (
                "text/plain, "
                "text/yaml, "
                "application/yaml, "
                "application/octet-stream;q=0.9, "
                "*/*;q=0.1"
            ),
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as response:
            content_type = response.headers.get("Content-Type", "")
            final_url = response.geturl()
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = None
                if declared_size is not None and declared_size > MAX_DOWNLOAD_BYTES:
                    raise ValueError(
                        f"规则源声明大小 {declared_size:,} bytes，超过上限 "
                        f"{MAX_DOWNLOAD_BYTES:,} bytes: {original_url}"
                    )

            data = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(data) > MAX_DOWNLOAD_BYTES:
                raise ValueError(
                    f"规则源超过最大允许大小 {MAX_DOWNLOAD_BYTES:,} bytes: {original_url}"
                )
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} 下载失败: {original_url}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"网络下载失败: {original_url}: {e.reason}") from e

    if looks_like_html(data, content_type):
        raise ValueError(
            "规则源返回 HTML 页面而不是规则文本："
            f"{original_url} -> {final_url} "
            f"(Content-Type: {content_type or 'unknown'})"
        )

    return decode_text_bytes(data, content_type)


def download_and_parse(url: str):
    content = download_text(url)
    parsed = parse_rules_from_content(content)
    validate_parsed_result(url, content, parsed)
    return url, parsed


def main():
    setup_dirs()
    log_handle = setup_logging()
    started = datetime.datetime.now()
    success_list = []
    source_success = 0
    source_failed = 0

    print("=" * 72)
    print("🚀 MRS ZH 规则构建开始")
    print(f"🕒 开始时间: {started.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📁 输出目录: {os.path.abspath(OUTPUT_DIR)}")
    print(f"📝 执行日志: {os.path.abspath(LOG_FILE)}")
    print("=" * 72)

    try:
        validate_config()

        group_order = [AD_EXCLUSION_GROUP] + [
            name for name in RULE_GROUPS if name != AD_EXCLUSION_GROUP
        ]
        prepared_groups = {}
        ad_baseline = None
        ad_keywords = set()

        # ========================================================
        # 阶段 1：下载、解析、聚合；先建立完整 Reject_Ads 基准
        # ========================================================
        for group_name in group_order:
            urls = RULE_GROUPS[group_name]
            print(f"\n🔄 正在处理规则组: {group_name} ...")
            all_suffixes = set()
            all_exacts = set()
            all_ipcidrs = set()
            all_others = set()
            group_success = 0
            group_failed = 0

            with ThreadPoolExecutor(max_workers=min(16, max(1, len(urls)))) as executor:
                futures = {executor.submit(download_and_parse, url): url for url in urls}
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        _, (suffs, exts, ips, oths, unknown_types) = future.result()
                        all_suffixes.update(suffs)
                        all_exacts.update(exts)
                        all_ipcidrs.update(ips)
                        all_others.update(oths)
                        if unknown_types:
                            summary = ", ".join(
                                f"{rule_type}={count}"
                                for rule_type, count in sorted(unknown_types.items())
                            )
                            print(f"  ⚠️ 检测到未知 Classical 规则类型: {summary}")
                        group_success += 1
                        source_success += 1
                        print(
                            f"  ✓ {url}\n"
                            f"    suffix={len(suffs):,}, exact={len(exts):,}, "
                            f"ipcidr={len(ips):,}, classical={len(oths):,}"
                        )
                    except Exception as e:
                        group_failed += 1
                        source_failed += 1
                        print(f"  ❌ 下载或解析失败 {url}: {e}")

            print(
                f"  📊 源处理结果: 成功 {group_success}/{len(urls)}，"
                f"失败 {group_failed}/{len(urls)}"
            )

            if group_success == 0:
                cleanup_group_outputs(group_name)
                if group_name == AD_EXCLUSION_GROUP:
                    raise RuntimeError(
                        f"{AD_EXCLUSION_GROUP} 所有源均失败，无法建立广告排除基准；"
                        "为避免其他规则组混入广告规则，本次构建终止。"
                    )
                print("  ❌ 本规则组所有源均失败，旧输出已清理，不生成该组结果。")
                continue

            optimized_ipcidrs = deduplicate_ip_networks(all_ipcidrs)

            # ----------------------------------------------------
            # Reject_Ads：先建立“完整”广告基准，不做 keyword 自身精简。
            # 这个完整基准会先用于所有其他规则组的重叠排除。
            # ----------------------------------------------------
            if group_name == AD_EXCLUSION_GROUP:
                print(
                    f"  🧹 开始域名去重。合并前域名数: "
                    f"{len(all_suffixes) + len(all_exacts):,}"
                )
                opt_suffixes, opt_exacts = deduplicate_domains(all_suffixes, all_exacts)
                print(
                    f"  ✨ 域名去重完成。优化后域名数: "
                    f"{len(opt_suffixes) + len(opt_exacts):,}"
                )

                ad_keywords = extract_ad_domain_keywords(all_others)
                ad_baseline = {
                    "suffixes": set(opt_suffixes),
                    "exacts": set(opt_exacts),
                    "ipcidrs": list(optimized_ipcidrs),
                    "others": set(all_others),
                }
                prepared_groups[group_name] = {
                    "suffixes": set(opt_suffixes),
                    "exacts": set(opt_exacts),
                    "ipcidrs": list(optimized_ipcidrs),
                    "others": set(all_others),
                }

                print(
                    "  🛡️ 完整广告排除基准已建立："
                    f"suffix={len(opt_suffixes):,}, "
                    f"exact={len(opt_exacts):,}, "
                    f"ipcidr={len(optimized_ipcidrs):,}, "
                    f"classical={len(all_others):,}, "
                    f"domain-keyword={len(ad_keywords):,}"
                )

                short_keywords = sorted(k for k in ad_keywords if len(k) <= 2)
                if short_keywords:
                    preview = ", ".join(short_keywords[:20])
                    more = " ..." if len(short_keywords) > 20 else ""
                    print(
                        "  ⚠️ Reject_Ads 含长度≤2的 DOMAIN-KEYWORD；"
                        "它们只用于 Reject_Ads 自身 Domain 精简，但仍可能覆盖大量广告域名："
                        f"{preview}{more}"
                    )
                if group_failed:
                    print(
                        f"  ⚠️ {AD_EXCLUSION_GROUP} 有 {group_failed:,} 个源失败，"
                        "本次广告排除基准可能不完整，请检查日志。"
                    )
                continue

            # ----------------------------------------------------
            # 其他规则组：只按 Reject_Ads 的直接 Domain/IP/Classical
            # 重叠关系排除；DOMAIN-KEYWORD 不参与域名子串排除。
            # ----------------------------------------------------
            if ad_baseline is None:
                raise RuntimeError(
                    f"尚未建立 {AD_EXCLUSION_GROUP} 广告排除基准，"
                    f"拒绝继续处理 {group_name}。"
                )

            all_suffixes, all_exacts, domain_stats = exclude_ad_domains(
                all_suffixes,
                all_exacts,
                ad_baseline["suffixes"],
                ad_baseline["exacts"],
            )
            optimized_ipcidrs, ip_stats = subtract_ad_ip_networks(
                optimized_ipcidrs,
                ad_baseline["ipcidrs"],
            )
            all_others, classical_removed = exclude_ad_classical(
                all_others,
                ad_baseline["others"],
            )

            removed_domain = domain_stats["suffix_removed"] + domain_stats["exact_removed"]
            print(
                "  🛡️ Reject_Ads 直接重叠排除完成："
                f"Domain={removed_domain:,} "
                f"(suffix={domain_stats['suffix_removed']:,}, "
                f"exact={domain_stats['exact_removed']:,})，"
                f"Classical={classical_removed:,}"
            )
            print(
                "  🛡️ IP 排除："
                f"输入 CIDR={ip_stats['input_networks']:,}，"
                f"完全删除={ip_stats['fully_removed']:,}，"
                f"部分拆分={ip_stats['partially_split']:,}，"
                f"排除地址数={ip_stats['removed_addresses']:,}，"
                f"输出 CIDR={ip_stats['output_networks']:,}"
            )
            if removed_domain == 0 and classical_removed == 0 and ip_stats["removed_addresses"] == 0:
                print("  ✓ 未发现与 Reject_Ads 直接重叠的规则。")

            if not any((all_suffixes, all_exacts, optimized_ipcidrs, all_others)):
                print("  ⚠️ 本规则组在广告重叠排除后没有剩余规则，旧输出将清理。")
                cleanup_group_outputs(group_name)
                continue

            print(
                f"  🧹 开始域名去重。合并前域名数: "
                f"{len(all_suffixes) + len(all_exacts):,}"
            )
            opt_suffixes, opt_exacts = deduplicate_domains(all_suffixes, all_exacts)
            print(
                f"  ✨ 域名去重完成。优化后域名数: "
                f"{len(opt_suffixes) + len(opt_exacts):,}"
            )

            prepared_groups[group_name] = {
                "suffixes": set(opt_suffixes),
                "exacts": set(opt_exacts),
                "ipcidrs": list(optimized_ipcidrs),
                "others": set(all_others),
            }

        # ========================================================
        # 阶段 2：所有其他组已完成 Ad 重叠排除之后，才使用
        # Reject_Ads DOMAIN-KEYWORD 精简 Reject_Ads 自己的域名规则。
        # ========================================================
        ad_group = prepared_groups.get(AD_EXCLUSION_GROUP)
        if ad_group is None:
            raise RuntimeError(f"{AD_EXCLUSION_GROUP} 未成功准备，无法继续生成输出。")

        before_ad_domains = len(ad_group["suffixes"]) + len(ad_group["exacts"])
        ad_group["suffixes"], ad_group["exacts"], keyword_stats = prune_ad_domains_by_keywords(
            ad_group["suffixes"],
            ad_group["exacts"],
            ad_keywords,
        )
        after_ad_domains = len(ad_group["suffixes"]) + len(ad_group["exacts"])
        print(
            f"\n🔎 {AD_EXCLUSION_GROUP} DOMAIN-KEYWORD 自身精简完成："
            f"精简前={before_ad_domains:,}，"
            f"移除={keyword_stats['total_removed']:,} "
            f"(suffix={keyword_stats['suffix_removed']:,}, "
            f"exact={keyword_stats['exact_removed']:,})，"
            f"保留={after_ad_domains:,}"
        )
        print(
            "  ℹ️ DOMAIN-KEYWORD 仅精简 Reject_Ads 自身域名；"
            "未用于其他规则组的域名子串排除。"
        )

        # ========================================================
        # 阶段 3：完成全部排除与精简后，统一生成 MRS / Classical。
        # ========================================================
        print("\n📦 开始生成最终规则集文件 ...")
        for group_name in group_order:
            group = prepared_groups.get(group_name)
            if group is None:
                continue

            opt_suffixes = group["suffixes"]
            opt_exacts = group["exacts"]
            optimized_ipcidrs = group["ipcidrs"]
            all_others = group["others"]
            expected_outputs = set()

            if not any((opt_suffixes, opt_exacts, optimized_ipcidrs, all_others)):
                print(f"  ⚠️ {group_name}: 最终没有可输出规则，清理旧文件。")
                cleanup_group_outputs(group_name)
                continue

            print(f"\n  ▶ 生成规则组: {group_name}")

            if opt_suffixes or opt_exacts:
                name = f"{group_name}_Domain"
                path = os.path.join(TEMP_DIR, f"{name}.txt")
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    for d in sorted(opt_suffixes):
                        f.write(f"+.{d}\n")
                    for d in sorted(opt_exacts):
                        f.write(f"{d}\n")
                count = len(opt_suffixes) + len(opt_exacts)
                if convert_to_mrs(path, 'text', 'domain', name):
                    filename = f"{name}.mrs"
                    expected_outputs.add(filename)
                    success_list.append((filename, 'domain', count))

            if optimized_ipcidrs:
                name = f"{group_name}_IP"
                path = os.path.join(TEMP_DIR, f"{name}.txt")
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    for ip in optimized_ipcidrs:
                        f.write(f"{ip}\n")
                count = len(optimized_ipcidrs)
                if convert_to_mrs(path, 'text', 'ipcidr', name):
                    filename = f"{name}.mrs"
                    expected_outputs.add(filename)
                    success_list.append((filename, 'ipcidr', count))

            if all_others:
                name = f"{group_name}_Classical"
                path = os.path.join(OUTPUT_DIR, f"{name}.txt")
                rules = sorted(all_others)
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    for rule in rules:
                        f.write(f"{rule}\n")
                if os.path.getsize(path) <= 0:
                    print(f"  ❌ Classical 文件异常为空: {path}")
                else:
                    print(
                        f"  📝 Classical text 已生成: {path} "
                        f"(共 {len(rules):,} 条规则)"
                    )
                    filename = f"{name}.txt"
                    expected_outputs.add(filename)
                    success_list.append((filename, 'classical', len(rules)))

            cleanup_group_outputs(group_name, keep=expected_outputs)

        update_readme(success_list)

        elapsed = datetime.datetime.now() - started
        print("\n" + "=" * 72)
        print("🏁 MRS ZH 规则构建结束")
        print(f"✅ 成功源: {source_success:,}")
        print(f"❌ 失败源: {source_failed:,}")
        print(f"📦 成功输出: {len(success_list):,} 个")
        print(f"⏱️ 总耗时: {elapsed.total_seconds():.2f} 秒")
        print(f"📝 日志文件: {LOG_FILE}")
        print("=" * 72)

        if source_failed:
            print("⚠️ 本次构建存在源失败，请检查日志；成功源的结果仍已生成。")

        return 0

    except Exception as e:
        print(f"\n💥 构建发生致命错误: {e}")
        traceback.print_exc()
        return 1
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            log_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
