import os
import re
import datetime
import urllib.request
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
from pathlib import Path


# ================= 扩展性配置区 =================
RULE_GROUPS = {
    "Reject_Ads": [
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
}


OUTPUT_DIR = "mrs_rules_ZH"
TEMP_DIR = os.path.join(OUTPUT_DIR, "TEMP")
README_FILE = "README.md"


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




def setup_dirs():
    """初始化输出和临时目录。"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)


_IPV4_LIKE_RE = re.compile(
    r"^\\d{1,3}(?:\\.\\d{1,3}){3}(?:/\\d{1,2})?$"
)
_IPV6_LIKE_RE = re.compile(
    r"^[0-9A-Fa-f:]+(?:/\\d{1,3})?$"
)


def is_ip_or_cidr(val: str) -> bool:
    """
    快速判断 IPv4/IPv6 地址或 CIDR。

    先用廉价的字符级筛选挡掉绝大多数域名，
    再交给 ipaddress 做严格校验，避免对海量域名逐条执行
    ipaddress 解析。
    """
    if _IPV4_LIKE_RE.fullmatch(val):
        try:
            ipaddress.ip_network(val, strict=False)
            return True
        except ValueError:
            return False

    if ":" in val and _IPV6_LIKE_RE.fullmatch(val):
        try:
            ipaddress.ip_network(val, strict=False)
            return True
        except ValueError:
            return False

    return False


def normalize_ip_cidr(val: str):
    """
    将纯 IP 转成单主机 CIDR，并规范化网络地址。
    IPv4 -> /32
    IPv6 -> /128
    CIDR -> strict=False 规范化
    """
    val = val.strip()
    try:
        if "/" in val:
            net = ipaddress.ip_network(val, strict=False)
        else:
            ip = ipaddress.ip_address(val)
            prefix = 32 if ip.version == 4 else 128
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return net
    except ValueError:
        return None


def normalize_domain(val: str) -> str:
    """标准化域名。"""
    val = val.strip().lower().rstrip(".")
    return val.lstrip(".")


def _canonical_classical(rule_type: str, value: str, extra: str = "") -> str:
    """
    保留 classical 规则语义。
    规则类型统一大写；规则参数尽量保持原始内容，不随意 lower。
    """
    rule_type = rule_type.strip().upper()
    value = value.strip()
    extra = extra.strip()

    if extra:
        return f"{rule_type},{value},{extra}"
    return f"{rule_type},{value}"


def parse_rules_from_content(content: str):
    """
    解析 Clash / Mihomo 规则文本。

    返回：
      suffixes : DOMAIN-SUFFIX / +.domain / .domain
      exacts   : DOMAIN / full:domain / PLAIN_DOMAIN_MODE=exact
      ipnets   : 已规范化的 IPv4/IPv6 网络对象
      classical: 除 domain/ip 外的完整 classical 规则

    设计原则：
      - domain.mrs 只接收 DOMAIN / DOMAIN-SUFFIX
      - ipcidr.mrs 只接收 IP / IP-CIDR / IP-CIDR6 / SRC-IP-CIDR
      - 其余带规则类型的规则完整进入 classical.txt
      - keyword/regexp 不再丢失
    """
    suffixes = set()
    exacts = set()
    ipnets = set()
    classical = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue
        if line.lower() == "payload:":
            continue

        # YAML list item
        if line.startswith("-"):
            line = line[1:].strip()

        if not line or line.startswith("#"):
            continue

        # YAML scalar quote
        if (
            len(line) >= 2
            and ((line[0] == "'" and line[-1] == "'")
                 or (line[0] == '"' and line[-1] == '"'))
        ):
            line = line[1:-1].strip()

        if not line:
            continue

        # ------------------------------------------------------------
        # Classical rule
        # ------------------------------------------------------------
        if "," in line:
            parts = [p.strip() for p in line.split(",", 2)]
            if len(parts) < 2:
                continue

            rule_type = parts[0].lower()
            val = parts[1]
            extra = parts[2] if len(parts) == 3 else ""

            if rule_type == "domain-suffix":
                domain = normalize_domain(val)
                if domain:
                    suffixes.add(domain)

            elif rule_type == "domain":
                domain = normalize_domain(val)
                if domain:
                    exacts.add(domain)

            elif rule_type in {
                "ip-cidr",
                "ip-cidr6",
                "src-ip-cidr",
            }:
                net = normalize_ip_cidr(val)
                if net is not None:
                    ipnets.add(net)
                else:
                    # 无法安全解析时，不静默丢弃，保留到 classical
                    classical.add(_canonical_classical(rule_type, val, extra))

            else:
                # 所有其它 classical 规则完整保留
                classical.add(_canonical_classical(rule_type, val, extra))

            continue

        # ------------------------------------------------------------
        # 非 classical domain / IP 表达式
        # ------------------------------------------------------------
        low = line.lower()

        if low.startswith("full:"):
            domain = normalize_domain(line[5:])
            if domain:
                exacts.add(domain)

        elif low.startswith("+."):
            domain = normalize_domain(line[2:])
            if domain:
                suffixes.add(domain)

        elif low.startswith("keyword:") or low.startswith("regexp:"):
            # 如果源本身已经使用 keyword:/regexp:，不能擅自转成 domain。
            # 为了保证“其他 -> classical”，转换成标准 classical 规则。
            prefix_name, value = line.split(":", 1)
            if value.strip():
                if prefix_name.lower() == "keyword":
                    classical.add(_canonical_classical("DOMAIN-KEYWORD", value))
                else:
                    classical.add(_canonical_classical("DOMAIN-REGEX", value))

        elif is_ip_or_cidr(line):
            net = normalize_ip_cidr(line)
            if net is not None:
                ipnets.add(net)

        elif line.startswith("."):
            domain = normalize_domain(line)
            if domain:
                suffixes.add(domain)

        else:
            # 纯文本 domain：保持原脚本 PLAIN_DOMAIN_MODE 语义
            domain = normalize_domain(line)
            if not domain:
                continue

            if PLAIN_DOMAIN_MODE == "suffix":
                suffixes.add(domain)
            else:
                exacts.add(domain)

    return suffixes, exacts, ipnets, classical


def deduplicate_domains(suffixes: set, exacts: set):
    """
    保持 DOMAIN-SUFFIX / DOMAIN 语义的域名去重。
    """
    sorted_suffixes = sorted(
        suffixes,
        key=lambda x: (x.count("."), x),
    )

    optimized_suffixes = set()

    for domain in sorted_suffixes:
        parts = domain.split(".")
        redundant = False

        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent.count(".") < 1:
                continue
            if parent in optimized_suffixes:
                redundant = True
                break

        if not redundant:
            optimized_suffixes.add(domain)

    optimized_exacts = set()

    for domain in exacts:
        parts = domain.split(".")
        covered = False

        # exact domain 被 suffix 覆盖
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            if parent.count(".") < 1:
                continue
            if parent in optimized_suffixes:
                covered = True
                break

        if not covered:
            optimized_exacts.add(domain)

    return optimized_suffixes, optimized_exacts


def deduplicate_ip_networks(networks):
    """
    真正进行 CIDR 去重/包含消除/相邻网段聚合。

    例如：
      1.2.3.4
      1.2.3.4/32
      1.2.3.0/24

    最终只保留：
      1.2.3.0/24

    使用 ipaddress.collapse_addresses，避免 O(n²) 的逐网段比较。
    """
    if not networks:
        return []

    # collapse_addresses 同时处理：
    # - 重复网络
    # - 被更大网络包含的网络
    # - 可以无损合并的相邻 CIDR
    return list(ipaddress.collapse_addresses(sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))))


def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str) -> bool:
    """调用 mihomo convert-ruleset 生成 MRS。"""
    out_file = os.path.join(OUTPUT_DIR, f"{output_name}.mrs")

    try:
        if os.path.exists(out_file):
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

        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ 转换失败: {output_name}")
        if e.stdout:
            print(e.stdout.strip())
        if e.stderr:
            print(e.stderr.strip())
        return False

    except FileNotFoundError:
        print("❌ 未找到 mihomo 命令，请确认 mihomo 已安装并在 PATH 中。")
        return False


def update_readme(success_files):
    """更新 README 中的自动生成规则订阅表。"""
    if not success_files:
        return

    repo = os.environ.get("GITHUB_REPOSITORY", "your-username/your-repo")
    branch = "main"

    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    now_str = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")

    md_content = (
        "\n### 📦 自动生成的规则集订阅链接 (ZH)\n\n"
        f"> ⏱ **最后同步时间**：`{now_str}` (UTC+8)\n\n"
        "| 文件名 | 规则类型 (Behavior) | 规则数量 | 下载链接 |\n"
        "| :--- | :---: | :---: | :--- |\n"
    )

    for filename, behavior, count in sorted(success_files, key=lambda x: x[0]):
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

    if not os.path.exists(README_FILE):
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(
                "# 规则集订阅列表\n\n"
                "## 基础规则\n"
                "<!-- RULES_START -->\n"
                "<!-- RULES_END -->\n\n"
                "## 合并与去重规则 (ZH)\n"
                "<!-- RULES_ZH_START -->\n"
                "<!-- RULES_ZH_END -->\n"
            )

    with open(README_FILE, "r", encoding="utf-8") as f:
        readme_content = f.read()

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
        new_content = pattern.sub(replacement, readme_content)
    else:
        new_content = readme_content + "\n\n" + replacement

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)


def download_text(url: str) -> str:
    """下载规则源并解码。"""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Mihomo-MRS-Builder)",
            "Accept": "text/plain, text/yaml, application/yaml, */*",
        },
    )

    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as response:
        data = response.read()

    return data.decode("utf-8-sig")


def fetch_and_parse(url: str):
    """并发 worker：下载 + 解析。"""
    content = download_text(url)
    parsed = parse_rules_from_content(content)
    return url, parsed


def process_group(group_name: str, urls):
    """
    处理单个规则组。

    下载阶段并发执行，解析阶段在线程 worker 中直接完成，
    避免先全部下载再串行解析。
    """
    print(f"\n🔄 正在处理规则组: {group_name} ...")

    all_suffixes = set()
    all_exacts = set()
    all_ipnets = set()
    all_classical = set()

    # 单组并发下载。
    # 线程主要等待网络 I/O；max_workers 过大反而容易触发 CDN 限流。
    workers = min(16, max(4, len(urls)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(fetch_and_parse, url): url
            for url in urls
        }

        for future in as_completed(future_map):
            url = future_map[future]

            try:
                (
                    _url,
                    (suffs, exts, ips, classical),
                ) = future.result()

                all_suffixes.update(suffs)
                all_exacts.update(exts)
                all_ipnets.update(ips)
                all_classical.update(classical)

                print(
                    f"  ✓ {url}\n"
                    f"    suffix={len(suffs):,}, "
                    f"exact={len(exts):,}, "
                    f"ipcidr={len(ips):,}, "
                    f"classical={len(classical):,}"
                )

            except Exception as e:
                print(f"  ❌ 下载或解析失败 {url}: {e}")

    if not any((all_suffixes, all_exacts, all_ipnets, all_classical)):
        print("  ⚠️ 本规则组没有解析出任何规则，跳过。")
        return []

    success_list = []

    # ============================================================
    # 1. Domain MRS
    # ============================================================
    opt_suffixes, opt_exacts = deduplicate_domains(
        all_suffixes,
        all_exacts,
    )

    print(
        f"  🧹 Domain 去重完成: "
        f"{len(all_suffixes) + len(all_exacts):,} -> "
        f"{len(opt_suffixes) + len(opt_exacts):,}"
    )

    if opt_suffixes or opt_exacts:
        domain_name = f"{group_name}_Domain"
        tmp_domain_path = os.path.join(
            TEMP_DIR,
            f"{domain_name}.txt",
        )

        domain_count = len(opt_suffixes) + len(opt_exacts)

        with open(
            tmp_domain_path,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:
            for domain in sorted(opt_suffixes):
                f.write(f"+.{domain}\n")

            for domain in sorted(opt_exacts):
                f.write(f"{domain}\n")

        if convert_to_mrs(
            tmp_domain_path,
            "text",
            "domain",
            domain_name,
        ):
            print(
                f"  ✅ 成功构建: {domain_name}.mrs "
                f"(共 {domain_count:,} 条规则)"
            )
            success_list.append(
                (f"{domain_name}.mrs", "domain", domain_count)
            )

    # ============================================================
    # 2. IP-CIDR MRS
    # ============================================================
    if all_ipnets:
        ip_name = f"{group_name}_IP"
        tmp_ip_path = os.path.join(
            TEMP_DIR,
            f"{ip_name}.txt",
        )

        optimized_ips = deduplicate_ip_networks(all_ipnets)
        ip_count = len(optimized_ips)

        print(
            f"  🧹 IP/CIDR 去重/聚合完成: "
            f"{len(all_ipnets):,} -> {ip_count:,}"
        )

        with open(
            tmp_ip_path,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:
            for net in optimized_ips:
                f.write(f"{net}\n")

        if convert_to_mrs(
            tmp_ip_path,
            "text",
            "ipcidr",
            ip_name,
        ):
            print(
                f"  ✅ 成功构建: {ip_name}.mrs "
                f"(共 {ip_count:,} 条规则)"
            )
            success_list.append(
                (f"{ip_name}.mrs", "ipcidr", ip_count)
            )

    # ============================================================
    # 3. Classical
    # ============================================================
    if all_classical:
        classical_name = f"{group_name}_Classical.txt"
        classical_path = os.path.join(
            OUTPUT_DIR,
            classical_name,
        )

        classical_sorted = sorted(
            all_classical,
            key=lambda x: x.casefold(),
        )

        with open(
            classical_path,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:
            for rule in classical_sorted:
                f.write(f"{rule}\n")

        classical_count = len(classical_sorted)

        print(
            f"  ✅ Classical 已生成: "
            f"{classical_name} "
            f"(共 {classical_count:,} 条规则)"
        )

        success_list.append(
            (classical_name, "classical", classical_count)
        )

    return success_list


def main():
    setup_dirs()

    success_list = []

    # 每个规则组内部并发下载。
    # 组之间仍保持串行，避免同时启动过多外部转换/写盘任务。
    for group_name, urls in RULE_GROUPS.items():
        success_list.extend(
            process_group(group_name, urls)
        )

    update_readme(success_list)


if __name__ == "__main__":
    main()
