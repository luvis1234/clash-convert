import os
import re
import datetime
import urllib.request
import subprocess
import ipaddress
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


def download_text(url: str) -> str:
    """
    下载规则源并解码。
    """

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
                "*/*"
            ),
        },
    )

    with urllib.request.urlopen(
        req,
        timeout=DOWNLOAD_TIMEOUT,
    ) as response:

        data = response.read()

    # UTF-8 优先，同时自动去除 BOM。
    return data.decode("utf-8-sig")


def download_and_parse(url: str):
    content=download_text(url)
    return url, parse_rules_from_content(content)


def main():
    setup_dirs()
    success_list=[]

    for group_name,urls in RULE_GROUPS.items():
        print(f"\n🔄 正在处理规则组: {group_name} ...")
        all_suffixes=set(); all_exacts=set(); all_ipcidrs=set(); all_others=set()

        with ThreadPoolExecutor(max_workers=min(16,max(1,len(urls)))) as executor:
            futures={executor.submit(download_and_parse,url):url for url in urls}
            for future in as_completed(futures):
                url=futures[future]
                try:
                    _,(suffs,exts,ips,oths)=future.result()
                    all_suffixes.update(suffs); all_exacts.update(exts); all_ipcidrs.update(ips); all_others.update(oths)
                    print(f"  ✓ {url}\n    suffix={len(suffs):,}, exact={len(exts):,}, ipcidr={len(ips):,}, classical={len(oths):,}")
                except Exception as e:
                    print(f"  ❌ 下载或解析失败 {url}: {e}")

        optimized_ipcidrs=deduplicate_ip_networks(all_ipcidrs)
        if not any((all_suffixes,all_exacts,optimized_ipcidrs,all_others)):
            print("  ⚠️ 本规则组没有解析出任何规则，跳过。")
            continue

        print(f"  🧹 开始域名去重。合并前域名数: {len(all_suffixes)+len(all_exacts):,}")
        opt_suffixes,opt_exacts=deduplicate_domains(all_suffixes,all_exacts)
        print(f"  ✨ 域名去重完成。优化后域名数: {len(opt_suffixes)+len(opt_exacts):,}")

        if opt_suffixes or opt_exacts:
            name=f"{group_name}_Domain"; path=os.path.join(TEMP_DIR,f"{name}.txt")
            with open(path,'w',encoding='utf-8',newline='\n') as f:
                for d in sorted(opt_suffixes): f.write(f"+.{d}\n")
                for d in sorted(opt_exacts): f.write(f"{d}\n")
            count=len(opt_suffixes)+len(opt_exacts)
            if convert_to_mrs(path,'text','domain',name): success_list.append((f"{name}.mrs",'domain',count))

        if optimized_ipcidrs:
            name=f"{group_name}_IP"; path=os.path.join(TEMP_DIR,f"{name}.txt")
            with open(path,'w',encoding='utf-8',newline='\n') as f:
                for ip in optimized_ipcidrs: f.write(f"{ip}\n")
            count=len(optimized_ipcidrs)
            if convert_to_mrs(path,'text','ipcidr',name): success_list.append((f"{name}.mrs",'ipcidr',count))

        if all_others:
            name=f"{group_name}_Classical"; path=os.path.join(OUTPUT_DIR,f"{name}.txt")
            rules=sorted(all_others)
            with open(path,'w',encoding='utf-8',newline='\n') as f:
                for rule in rules: f.write(f"{rule}\n")
            print(f"  📝 Classical text 已生成: {path} (共 {len(rules):,} 条规则)")
            success_list.append((f"{name}.txt",'classical',len(rules)))

    update_readme(success_list)


if __name__ == "__main__":
    main()
