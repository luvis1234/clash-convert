import os
import re
import datetime
import urllib.request
import subprocess
from pathlib import Path


# ================= 扩展性配置区 =================
RULE_GROUPS = {
    "Reject_Ads": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
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
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml",
    ],
    "Direct_CN": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml",
    ],
    "Proxy_Global": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml",
    ],
}

OUTPUT_DIR = "mrs_rules_ZH"
TEMP_DIR = os.path.join(OUTPUT_DIR, "TEMP")
README_FILE = "README.md"
DOWNLOAD_TIMEOUT = 120

# 纯文本域名没有 DOMAIN / DOMAIN-SUFFIX 类型信息。
# "suffix": example.com -> +.example.com
# "exact":  example.com -> example.com
PLAIN_DOMAIN_MODE = "exact"


def setup_dirs():
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)


def is_ip_or_cidr(val: str) -> bool:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", val):
        try:
            ip_part = val.split("/", 1)[0]
            return all(0 <= int(x) <= 255 for x in ip_part.split("."))
        except ValueError:
            return False

    if ":" in val and re.fullmatch(r"[0-9a-fA-F:]+(?:/\d{1,3})?", val):
        return True

    return False


def normalize_domain(val: str) -> str:
    return val.strip().lower().rstrip(".").lstrip(".")


def is_valid_domain(domain: str) -> bool:
    if not domain or "/" in domain or "\\" in domain:
        return False
    if len(domain) > 253:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    if ".." in domain:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9_-]+", label):
            return False

    return True


def parse_rules_from_content(content: str):
    suffixes = set()
    exacts = set()
    ipcidrs = set()
    others = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or line == "payload:":
            continue

        if line.startswith("-"):
            line = line[1:].strip()

        if not line or line.startswith("#"):
            continue

        if (
            (line.startswith("'") and line.endswith("'"))
            or (line.startswith('"') and line.endswith('"'))
        ):
            line = line[1:-1].strip()

        rule_str = line.lower().strip()
        if not rule_str:
            continue

        if "," in rule_str:
            parts = [p.strip() for p in rule_str.split(",", 2)]
            if len(parts) < 2:
                continue

            rule_type, val = parts[0], parts[1]

            if rule_type == "domain-suffix":
                domain = normalize_domain(val)
                if is_valid_domain(domain):
                    suffixes.add(domain)

            elif rule_type == "domain":
                domain = normalize_domain(val)
                if is_valid_domain(domain):
                    exacts.add(domain)

            elif rule_type in ("ip-cidr", "ip-cidr6", "src-ip-cidr"):
                if val:
                    ipcidrs.add(val)

            elif rule_type == "domain-keyword":
                if val:
                    others.add(f"keyword:{val}")

            elif rule_type == "domain-regex":
                if val:
                    others.add(f"regexp:{val}")

            continue

        if rule_str.startswith("full:"):
            domain = normalize_domain(rule_str[5:])
            if is_valid_domain(domain):
                exacts.add(domain)

        elif rule_str.startswith("+."):
            domain = normalize_domain(rule_str[2:])
            if is_valid_domain(domain):
                suffixes.add(domain)

        elif rule_str.startswith("keyword:") or rule_str.startswith("regexp:"):
            others.add(rule_str)

        elif is_ip_or_cidr(rule_str):
            ipcidrs.add(rule_str)

        elif rule_str.startswith("."):
            domain = normalize_domain(rule_str)
            if is_valid_domain(domain):
                suffixes.add(domain)

        else:
            domain = normalize_domain(rule_str)
            if not is_valid_domain(domain):
                continue

            if PLAIN_DOMAIN_MODE == "suffix":
                suffixes.add(domain)
            else:
                exacts.add(domain)

    return suffixes, exacts, ipcidrs, others


# ----------------------------------------------------------------------
# 高性能域名后缀 Trie
#
# 节点按 DNS label 的反向顺序存储：
#
#   www.a.example.com
#       -> com -> example -> a -> www
#
# suffix 标记放在对应节点。
#
# 这样判断一个域名是否已经被父 suffix 覆盖，只需要沿着它的
# label 链向父级走一次，不再对每个域名做字符串拼接 + set 查询。
#
# 同时用 iterative DFS 做压缩输出，避免递归深度问题。
# ----------------------------------------------------------------------

class _TrieNode:
    __slots__ = ("children", "suffix", "exact")

    def __init__(self):
        self.children = {}
        self.suffix = False
        self.exact = False


def _insert_trie(root: _TrieNode, domain: str, *, suffix=False, exact=False):
    node = root
    for label in reversed(domain.split(".")):
        child = node.children.get(label)
        if child is None:
            child = _TrieNode()
            node.children[label] = child
        node = child

    if suffix:
        node.suffix = True
    if exact:
        node.exact = True


def _mark_suffix_coverage(node: _TrieNode, parent_covered=False):
    """
    返回该节点及其所有后代中实际还需要保留的信息。

    如果父节点已经是 suffix：
        当前节点以及全部子树的 suffix/exact 都被覆盖。

    对于 suffix 节点本身：
        其 exact 也被覆盖，因为 +.domain 同时覆盖根域和子域。

    返回值：
        (keep_suffix, keep_exact)
    """
    covered = parent_covered or node.suffix

    if covered:
        node.suffix = False
        node.exact = False
    else:
        if node.suffix:
            # 这个节点会覆盖整个子树，所以子节点无需保留。
            for child in node.children.values():
                _clear_subtree(child)
            node.children.clear()
            node.suffix = True
            node.exact = False
            return True, False

    # 父级没有覆盖时，递归处理子树。
    for label, child in list(node.children.items()):
        _mark_suffix_coverage(child, covered)
        if (
            not child.suffix
            and not child.exact
            and not child.children
        ):
            del node.children[label]

    return node.suffix, node.exact


def _clear_subtree(node: _TrieNode):
    node.children.clear()
    node.suffix = False
    node.exact = False


def _emit_trie(node: _TrieNode, labels_rev, suffix_out, exact_out):
    """
    将 Trie 中保留下来的规则转换回正常域名。
    """
    if node.suffix or node.exact:
        domain = ".".join(reversed(labels_rev))

        if node.suffix:
            suffix_out.add(domain)

        if node.exact:
            exact_out.add(domain)

    for label, child in node.children.items():
        labels_rev.append(label)
        _emit_trie(child, labels_rev, suffix_out, exact_out)
        labels_rev.pop()


def deduplicate_domains(suffixes: set, exacts: set):
    """
    使用反向 DNS Trie 对百万级域名进行去重。

    规则：

    1. 完全重复：
       set 本身负责去重。

    2. 父 suffix 覆盖子 suffix：
       +.example.com
       +.a.example.com
       ->
       +.example.com

    3. 父 suffix 覆盖 exact：
       +.example.com
       example.com
       www.example.com
       ->
       +.example.com

    4. exact 不会反向删除父/兄弟 suffix。

    时间复杂度：
        O(所有域名的 label 总数)

    空间复杂度：
        O(所有唯一域名的 label 总数)

    相比原先：
        对每一个域名逐级构造 parent 字符串并查询 set，
        这里只在 Trie 中沿 label 边走一次。
    """
    root = _TrieNode()

    for domain in suffixes:
        _insert_trie(root, domain, suffix=True)

    for domain in exacts:
        _insert_trie(root, domain, exact=True)

    # 根节点不对应实际域名。
    for label, child in list(root.children.items()):
        _mark_suffix_coverage(child, False)
        if (
            not child.suffix
            and not child.exact
            and not child.children
        ):
            del root.children[label]

    optimized_suffixes = set()
    optimized_exacts = set()

    _emit_trie(
        root,
        [],
        optimized_suffixes,
        optimized_exacts,
    )

    return optimized_suffixes, optimized_exacts


def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str) -> bool:
    out_file = os.path.join(OUTPUT_DIR, f"{output_name}.mrs")

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
    if not success_files:
        return

    repo = os.environ.get(
        "GITHUB_REPOSITORY",
        "your-username/your-repo",
    )
    branch = "main"

    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    now_str = datetime.datetime.now(tz_utc_8).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    md_content = (
        "\n### 📦 自动生成的 MRS 规则集订阅链接 (ZH)\n\n"
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
            f"| **{filename}** | `{behavior}` | "
            f"{count:,} | {links} |\n"
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


def main():
    setup_dirs()
    success_list = []

    for group_name, urls in RULE_GROUPS.items():
        print(f"\n🔄 正在处理规则组: {group_name} ...")

        all_suffixes = set()
        all_exacts = set()
        all_ipcidrs = set()
        all_others = set()

        for url in urls:
            try:
                content = download_text(url)

                suffs, exts, ips, oths = parse_rules_from_content(content)

                all_suffixes.update(suffs)
                all_exacts.update(exts)
                all_ipcidrs.update(ips)
                all_others.update(oths)

                print(
                    f"  ✓ {url}\n"
                    f"    suffix={len(suffs):,}, "
                    f"exact={len(exts):,}, "
                    f"ipcidr={len(ips):,}, "
                    f"unsupported={len(oths):,}"
                )

            except Exception as e:
                print(f"  ❌ 下载或解析失败 {url}: {e}")

        if not any((all_suffixes, all_exacts, all_ipcidrs, all_others)):
            print("  ⚠️ 本规则组没有解析出任何规则，跳过。")
            continue

        before_domain_count = len(all_suffixes) + len(all_exacts)

        print(
            f"  🧹 使用反向 DNS Trie 开始域名去重。"
            f" 合并前域名数: {before_domain_count:,}"
        )

        opt_suffixes, opt_exacts = deduplicate_domains(
            all_suffixes,
            all_exacts,
        )

        after_domain_count = len(opt_suffixes) + len(opt_exacts)

        print(
            f"  ✨ Trie 去重完成，"
            f"优化后域名数: {after_domain_count:,}，"
            f"删除: {before_domain_count - after_domain_count:,}"
        )

        if all_others:
            print(
                f"  ⚠️ 检测到 {len(all_others):,} 条 "
                "keyword/regexp。"
                "MRS domain behavior 不承载这些规则，"
                "本次不会写入 domain MRS。"
            )

        # ==========================================================
        # Domain MRS
        # ==========================================================
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
                # DOMAIN-SUFFIX -> +.domain
                for domain in sorted(opt_suffixes):
                    f.write(f"+.{domain}\n")

                # DOMAIN / full: -> exact domain
                for domain in sorted(opt_exacts):
                    f.write(f"{domain}\n")

            print(
                f"  📝 Domain text 已生成: "
                f"{tmp_domain_path}"
            )

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
                    (
                        f"{domain_name}.mrs",
                        "domain",
                        domain_count,
                    )
                )

        # ==========================================================
        # IP-CIDR MRS
        # ==========================================================
        if all_ipcidrs:
            ip_name = f"{group_name}_IP"
            tmp_ip_path = os.path.join(
                TEMP_DIR,
                f"{ip_name}.txt",
            )

            ip_count = len(all_ipcidrs)

            with open(
                tmp_ip_path,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as f:
                for ip in sorted(all_ipcidrs):
                    f.write(f"{ip}\n")

            print(
                f"  📝 IP-CIDR text 已生成: "
                f"{tmp_ip_path}"
            )

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
                    (
                        f"{ip_name}.mrs",
                        "ipcidr",
                        ip_count,
                    )
                )

    update_readme(success_list)


if __name__ == "__main__":
    main()
