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
        "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/data.txt",
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
        "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/rule/Custom_Direct_Domain.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml",
    ],
    "Proxy_Global": [
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy_Classical.yaml",
         ],

    "mydirect": [
        "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/mydirect.txt",
         ],
    "AI": [
        "https://raw.githubusercontent.com/viewer12/OverseasAI.list/main/rule/Clash/OverseasAI/OverseasAI.list",
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Ruleset/AI.list",
        "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Gemini/Gemini.yaml",
        "https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/refs/heads/main/rules/clash/global.yaml",
        "https://raw.githubusercontent.com/DustinWin/domain-list-custom/refs/heads/domains/ai.list",
         ],
    
}


OUTPUT_DIR = "mrs_rules_ZH"
TEMP_DIR = os.path.join(OUTPUT_DIR, "TEMP")
README_FILE = "README.md"
LOG_FILE = os.path.join(OUTPUT_DIR, "build_mrs_zh.log")

# 防呆参数
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024  # 单个规则源最大 64 MiB
VALID_PLAIN_DOMAIN_MODES = {"exact", "suffix"}


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
    """初始化输出和临时目录。"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)



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
    suffixes, exacts, ipcidrs, others = parsed
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
    """解析 Clash/Mihomo 规则，并严格分离 Domain、目标 IP 和 Classical。"""
    suffixes, exacts, ipcidrs, others = set(), set(), set(), set()

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
            if typ=='domain-suffix': add_domain(suffixes,val,'DOMAIN-SUFFIX')
            elif typ=='domain': add_domain(exacts,val,'DOMAIN')
            elif typ in ('ip-cidr','ip-cidr6'):
                cidr=canonical_ip_cidr(val)
                if cidr: ipcidrs.add(cidr)
                elif val: others.add(rule)
            elif typ=='src-ip-cidr':
                if val: others.add(rule)
            elif typ in ('domain-keyword','domain-regex'):
                if val: others.add(rule)
            else:
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

    return suffixes,exacts,ipcidrs,others


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
    # README 不存在时创建基础结构
    # --------------------------------------------------------
    if not os.path.exists(README_FILE):

        with open(
            README_FILE,
            "w",
            encoding="utf-8",
        ) as f:

            f.write(
                "# 规则集订阅列表\n\n"
                "## 基础规则\n"
                "<!-- RULES_START -->\n"
                "<!-- RULES_END -->\n\n"
                "## 合并与去重规则 (ZH)\n"
                "<!-- RULES_ZH_START -->\n"
                "<!-- RULES_ZH_END -->\n"
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
    pattern = re.compile(
        r"<!-- RULES_ZH_START -->.*<!-- RULES_ZH_END -->",
        re.DOTALL,
    )

    replacement = (
        "<!-- RULES_ZH_START -->\n"
        f"{md_content}\n"
        "<!-- RULES_ZH_END -->"
    )

    if pattern.search(readme_content):

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


def decode_text_bytes(data: bytes, content_type: str = "") -> str:
    """
    解码规则文本。优先 UTF-8/UTF-8 BOM；必要时兼容 GB18030。
    不使用 errors='replace'，避免静默制造真正的乱码。
    """
    # 优先使用 HTTP charset（若明确提供）
    charset = None
    m = re.search(r"charset=([\w.\-]+)", content_type or "", re.IGNORECASE)
    if m:
        charset = m.group(1).strip('"\'').lower()

    candidates = []
    if charset:
        candidates.append(charset)
    candidates.extend(["utf-8-sig", "utf-8", "gb18030"])

    tried = set()
    for enc in candidates:
        if enc in tried:
            continue
        tried.add(enc)
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass

    raise UnicodeDecodeError(
        "unknown", data, 0, min(len(data), 1),
        "无法按 UTF-8/GB18030 解码规则源"
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

        for group_name, urls in RULE_GROUPS.items():
            print(f"\n🔄 正在处理规则组: {group_name} ...")
            all_suffixes = set(); all_exacts = set(); all_ipcidrs = set(); all_others = set()
            group_success = 0
            group_failed = 0

            with ThreadPoolExecutor(max_workers=min(16, max(1, len(urls)))) as executor:
                futures = {executor.submit(download_and_parse, url): url for url in urls}
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        _, (suffs, exts, ips, oths) = future.result()
                        all_suffixes.update(suffs); all_exacts.update(exts); all_ipcidrs.update(ips); all_others.update(oths)
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

            print(f"  📊 源处理结果: 成功 {group_success}/{len(urls)}，失败 {group_failed}/{len(urls)}")

            if group_success == 0:
                print("  ❌ 本规则组所有源均失败，为防止旧文件冒充新结果，不生成该组输出。")
                continue

            optimized_ipcidrs = deduplicate_ip_networks(all_ipcidrs)
            if not any((all_suffixes, all_exacts, optimized_ipcidrs, all_others)):
                print("  ⚠️ 本规则组没有解析出任何规则，跳过。")
                continue

            print(f"  🧹 开始域名去重。合并前域名数: {len(all_suffixes)+len(all_exacts):,}")
            opt_suffixes, opt_exacts = deduplicate_domains(all_suffixes, all_exacts)
            print(f"  ✨ 域名去重完成。优化后域名数: {len(opt_suffixes)+len(opt_exacts):,}")

            if opt_suffixes or opt_exacts:
                name = f"{group_name}_Domain"; path = os.path.join(TEMP_DIR, f"{name}.txt")
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    for d in sorted(opt_suffixes): f.write(f"+.{d}\n")
                    for d in sorted(opt_exacts): f.write(f"{d}\n")
                count = len(opt_suffixes) + len(opt_exacts)
                if convert_to_mrs(path, 'text', 'domain', name):
                    success_list.append((f"{name}.mrs", 'domain', count))

            if optimized_ipcidrs:
                name = f"{group_name}_IP"; path = os.path.join(TEMP_DIR, f"{name}.txt")
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    for ip in optimized_ipcidrs: f.write(f"{ip}\n")
                count = len(optimized_ipcidrs)
                if convert_to_mrs(path, 'text', 'ipcidr', name):
                    success_list.append((f"{name}.mrs", 'ipcidr', count))

            if all_others:
                name = f"{group_name}_Classical"; path = os.path.join(OUTPUT_DIR, f"{name}.txt")
                rules = sorted(all_others)
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    for rule in rules: f.write(f"{rule}\n")
                if os.path.getsize(path) <= 0:
                    print(f"  ❌ Classical 文件异常为空: {path}")
                else:
                    print(f"  📝 Classical text 已生成: {path} (共 {len(rules):,} 条规则)")
                    success_list.append((f"{name}.txt", 'classical', len(rules)))

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

        # 部分源失败时仍允许成功结果输出，但给 CI 一个明确告警。
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
            # 不主动关闭 sys.stdout/sys.stderr 包装器，只关闭底层日志句柄前先恢复终端。
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            log_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
