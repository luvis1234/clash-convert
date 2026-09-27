import os
import re
import datetime
import urllib.request
import subprocess
from pathlib import Path


# ================= 扩展性配置区 =================
RULE_GROUPS = {
    "Reject_Ads": [
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
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
DOWNLOAD_TIMEOUT = 120


def setup_dirs():
    """初始化输出和临时目录。"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)


def is_ip_or_cidr(val: str) -> bool:
    """
    判断字符串是否为 IPv4 / IPv6 地址或 CIDR。
    """

    # --------------------------------------------------------
    # IPv4 / IPv4 CIDR
    # --------------------------------------------------------
    if re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?",
        val,
    ):
        try:
            ip_part = val.split("/", 1)[0]
            octets = ip_part.split(".")

            return all(
                0 <= int(octet) <= 255
                for octet in octets
            )

        except ValueError:
            return False

    # --------------------------------------------------------
    # IPv6 / IPv6 CIDR
    #
    # 保持宽松判断，最终交给 Mihomo ipcidr 转换器校验。
    # --------------------------------------------------------
    if ":" in val and re.fullmatch(
        r"[0-9a-fA-F:]+(?:/\d{1,3})?",
        val,
    ):
        return True

    return False


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
    """
    解析 Clash / Mihomo 规则文本。

    返回：

        suffixes
            DOMAIN-SUFFIX
            +.domain
            .domain
            纯文本 domain（默认 suffix）

        exacts
            DOMAIN
            full:domain

        ipcidrs
            IP-CIDR
            IP-CIDR6
            SRC-IP-CIDR
            纯文本 IP / CIDR

        others
            DOMAIN-KEYWORD
            DOMAIN-REGEX

    ============================================================
    关键语义
    ============================================================

    DOMAIN-SUFFIX,example.com
        ->
    +.example.com

    DOMAIN,example.com
        ->
    example.com

    +.example.com
        ->
    +.example.com

    .example.com
        ->
    +.example.com

    full:example.com
        ->
    example.com

    纯文本 example.com
        ->
    +.example.com
    （PLAIN_DOMAIN_MODE = "suffix"）

    ============================================================
    为什么必须输出 +.domain？
    ============================================================

    Mihomo 的 DomainSetBuilder 区分：

        example.com
            精确匹配 example.com

        .example.com
            suffix-only

        +.example.com
            根域 + 所有子域

    因此 DOMAIN-SUFFIX 不能直接写成：

        example.com

    否则会丢失 suffix 语义。
    """

    suffixes = set()
    exacts = set()
    ipcidrs = set()
    others = set()

    for raw_line in content.splitlines():

        line = raw_line.strip()

        # --------------------------------------------------------
        # 空行 / 注释 / YAML payload 标记
        # --------------------------------------------------------
        if not line:
            continue

        if line.startswith("#"):
            continue

        if line == "payload:":
            continue

        # --------------------------------------------------------
        # YAML 列表项
        #
        # - DOMAIN-SUFFIX,example.com
        # ->
        # DOMAIN-SUFFIX,example.com
        # --------------------------------------------------------
        if line.startswith("-"):
            line = line[1:].strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # --------------------------------------------------------
        # 去除 YAML 外层引号
        # --------------------------------------------------------
        if (
            (line.startswith("'") and line.endswith("'"))
            or
            (line.startswith('"') and line.endswith('"'))
        ):
            line = line[1:-1].strip()

        if not line:
            continue

        rule_str = line.lower().strip()

        if not rule_str:
            continue

        # ========================================================
        # Classical Rule
        #
        # DOMAIN-SUFFIX,xxx
        # DOMAIN,xxx
        # IP-CIDR,xxx
        # DOMAIN-KEYWORD,xxx
        # DOMAIN-REGEX,xxx
        # ========================================================
        if "," in rule_str:

            parts = [
                p.strip()
                for p in rule_str.split(",", 2)
            ]

            if len(parts) < 2:
                continue

            rule_type = parts[0]
            val = parts[1]

            # ----------------------------------------------------
            # DOMAIN-SUFFIX
            #
            # 必须保留 suffix 语义。
            # 后续生成 MRS domain text 时：
            #
            #     +.example.com
            #
            # ----------------------------------------------------
            if rule_type == "domain-suffix":

                domain = normalize_domain(val)

                if domain:
                    suffixes.add(domain)

            # ----------------------------------------------------
            # DOMAIN
            #
            # 精确匹配。
            #
            # MRS domain text：
            #
            #     example.com
            #
            # ----------------------------------------------------
            elif rule_type == "domain":

                domain = normalize_domain(val)

                if domain:
                    exacts.add(domain)

            # ----------------------------------------------------
            # IP-CIDR
            # ----------------------------------------------------
            elif rule_type in (
                "ip-cidr",
                "ip-cidr6",
                "src-ip-cidr",
            ):

                if val:
                    ipcidrs.add(val)

            # ----------------------------------------------------
            # DOMAIN-KEYWORD
            #
            # domain behavior 的 MRS 不直接承载 keyword。
            # 因此保留到 others，仅用于日志提示。
            # ----------------------------------------------------
            elif rule_type == "domain-keyword":

                if val:
                    others.add(f"keyword:{val}")

            # ----------------------------------------------------
            # DOMAIN-REGEX
            #
            # 同样不写入 domain MRS。
            # ----------------------------------------------------
            elif rule_type == "domain-regex":

                if val:
                    others.add(f"regexp:{val}")

            continue

        # ========================================================
        # Domain Text / MRS Domain Syntax
        # ========================================================

        # --------------------------------------------------------
        # full:example.com
        #
        # 明确表示精确匹配。
        # --------------------------------------------------------
        if rule_str.startswith("full:"):

            domain = normalize_domain(
                rule_str[5:]
            )

            if domain:
                exacts.add(domain)

        # --------------------------------------------------------
        # +.example.com
        #
        # Mihomo：
        #
        #     根域 + 所有子域
        # --------------------------------------------------------
        elif rule_str.startswith("+."):

            domain = normalize_domain(
                rule_str[2:]
            )

            if domain:
                suffixes.add(domain)

        # --------------------------------------------------------
        # keyword: / regexp:
        #
        # domain MRS 不支持。
        # --------------------------------------------------------
        elif (
            rule_str.startswith("keyword:")
            or
            rule_str.startswith("regexp:")
        ):

            others.add(rule_str)

        # --------------------------------------------------------
        # IP / CIDR
        # --------------------------------------------------------
        elif is_ip_or_cidr(rule_str):

            ipcidrs.add(rule_str)

        # --------------------------------------------------------
        # .example.com
        #
        # Mihomo DomainSet 中表示 suffix-only。
        #
        # 本脚本希望保留 DOMAIN-SUFFIX 的根域 + 子域语义，
        # 所以统一转换为 suffix 集合，最终输出 +.example.com。
        # --------------------------------------------------------
        elif rule_str.startswith("."):

            domain = normalize_domain(rule_str)

            if domain:
                suffixes.add(domain)

        # --------------------------------------------------------
        # 纯文本 domain
        #
        # 例如：
        #
        #     example.com
        #
        # 没有 DOMAIN / DOMAIN-SUFFIX 类型信息。
        # --------------------------------------------------------
        else:

            domain = normalize_domain(rule_str)

            if not domain:
                continue

            if PLAIN_DOMAIN_MODE == "suffix":

                suffixes.add(domain)

            else:

                exacts.add(domain)

    return (
        suffixes,
        exacts,
        ipcidrs,
        others,
    )


def _reverse_label_key(domain: str) -> str:
    """
    把域名的 label 顺序反转，TLD 放到最前面。

        example.com     -> com.example
        a.example.com   -> com.example.a
        b.a.example.com -> com.example.a.b

    这样任何"子域名"反转后的字符串，必然以其"父域名"反转后的
    字符串为前缀（且紧跟一个 "." 分隔符）。配合排序，所有拥有
    共同祖先的域名会在排序结果中连续排列在一起，父域名必然排在
    它自己所有子域名的前面——这正是 mihomo 内核构建
    DomainTrie / DomainSet 时按 label 反向组织的核心思路，这里
    用"排序 + 前缀比较"达到等价效果，但不需要真正建一棵树。
    """
    return ".".join(reversed(domain.split(".")))


def deduplicate_domains(
    suffixes: set,
    exacts: set,
):
    """
    去重，同时保持 DOMAIN-SUFFIX / DOMAIN 的语义。

    ============================================================
    规则（与旧实现完全一致，仅内部算法替换）
    ============================================================

    1. 父 suffix 已存在时：

        example.com
        a.example.com
        b.a.example.com

    只需要：

        +.example.com

    2. exact 被 suffix 覆盖：

        suffix:
            example.com

        exact:
            www.example.com

    则：

        www.example.com

    无需额外保留。

    3. exact 与 suffix 不能反向合并。

        DOMAIN,example.com

    不能因为存在：

        DOMAIN-SUFFIX,www.example.com

    而删除。

    ============================================================
    为什么要重写（百万级域名规模下的性能问题）
    ============================================================

    旧实现对每个域名都执行：

        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])      # 每层一次 O(D) 字符串拼接
            if parent in optimized_suffixes:  # 每层一次 hash 查找
                ...

    单个域名的判断是 O(D^2)（D = label 数），且每一层都会产生一个
    新的临时字符串对象；域名到百万级规模时，海量字符串拼接和随之
    而来的 GC 压力是主要瓶颈。

    ============================================================
    新实现思路：反转排序 + 单趟线性扫描
    ============================================================

    （最初尝试过手写一棵 Trie 树，语义完全等价，但实测在"层级深、
    重叠度低"的场景下，Python 里创建大量节点对象/字典的开销反而
    比旧实现更慢；下面这版把所有重活都交给 CPython 用 C 实现的
    `sort()` 和 `str.startswith`，避免了逐层的 Python 级循环，
    实测比旧实现更快，且规模越大优势越明显。）

    步骤：

        1. 把每个域名反转成 "TLD 在前" 的 key
           （见 _reverse_label_key）。

        2. suffix 和 exact 一起排序：
           - key 相同时 suffix 排在 exact 前面，这样"同一个域名
             既是 DOMAIN 又是 DOMAIN-SUFFIX"时，suffix 会先被
             接受，exact 再被判定为冗余。

        3. 排序后，任意一条链上的祖先必然紧邻出现在它所有子域名
           之前（前缀排序的性质）。因此只需要维护一个 anchor
           （当前有效的、至少二级的祖先 suffix key），线性扫描
           一遍即可：

           - 命中 anchor 前缀（且下一个字符是 "." 或恰好相等）
             -> 冗余，跳过。
           - 未命中 -> 接受；如果这是一个合法的 suffix（至少二级
             域名），更新 anchor。

        由于排序具有"祖先必然连续排在子孙之前"的性质，即使中间
        某个祖先自身被判定为冗余而未被接受，anchor 仍然停留在
        更上一级"真正被接受"的祖先上，后续子孙依旧能正确判断为
        被覆盖（等价于旧实现里逐层向上查找的效果）。

        单裸 TLD（如 "com"）永远不会被当作合法祖先使用（不更新
        anchor），与旧实现里 `parent.count(".") < 1` 时跳过的
        效果完全一致。
    ============================================================
    """

    # tag: 0 = suffix, 1 = exact；(key, tag, domain) 三元组直接
    # 排序，key 相同时 tag 小的（suffix）排在前面。
    combined = [
        (_reverse_label_key(d), 0, d) for d in suffixes
    ] + [
        (_reverse_label_key(d), 1, d) for d in exacts
    ]

    combined.sort()

    optimized_suffixes = set()
    optimized_exacts = set()

    anchor = None  # 当前有效的（至少二级域名）祖先 suffix 的 key

    for key, tag, domain in combined:

        covered = (
            anchor is not None
            and key.startswith(anchor)
            and (
                len(key) == len(anchor)
                or key[len(anchor)] == "."
            )
        )

        if tag == 0:

            if covered:
                continue

            optimized_suffixes.add(domain)

            # 只有"至少二级域名"才能作为后续判断的合法祖先，
            # 裸 TLD（如 "com"）不更新 anchor。
            if domain.count(".") >= 1:
                anchor = key

        else:

            if covered:
                continue

            optimized_exacts.add(domain)

    return (
        optimized_suffixes,
        optimized_exacts,
    )


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


def main():

    setup_dirs()

    success_list = []

    # ========================================================
    # 逐组处理规则
    # ========================================================
    for group_name, urls in RULE_GROUPS.items():

        print(
            f"\n🔄 正在处理规则组: "
            f"{group_name} ..."
        )

        all_suffixes = set()
        all_exacts = set()
        all_ipcidrs = set()
        all_others = set()

        # ====================================================
        # 下载并解析每个规则源
        # ====================================================
        for url in urls:

            try:

                content = download_text(url)

                (
                    suffs,
                    exts,
                    ips,
                    oths,
                ) = parse_rules_from_content(
                    content
                )

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

                print(
                    f"  ❌ 下载或解析失败 "
                    f"{url}: {e}"
                )

        # ====================================================
        # 检查是否有任何规则
        # ====================================================
        if not any(
            (
                all_suffixes,
                all_exacts,
                all_ipcidrs,
                all_others,
            )
        ):

            print(
                "  ⚠️ 本规则组没有解析出任何规则，"
                "跳过。"
            )

            continue

        # ====================================================
        # 域名去重
        # ====================================================
        print(
            f"  🧹 开始域名去重。"
            f"合并前域名数: "
            f"{len(all_suffixes) + len(all_exacts):,}"
        )

        (
            opt_suffixes,
            opt_exacts,
        ) = deduplicate_domains(
            all_suffixes,
            all_exacts,
        )

        print(
            f"  ✨ 去重完成，"
            f"优化后域名数: "
            f"{len(opt_suffixes) + len(opt_exacts):,}"
        )

        # ====================================================
        # keyword / regexp
        # ====================================================
        if all_others:

            print(
                f"  ⚠️ 检测到 "
                f"{len(all_others):,} 条 "
                f"keyword/regexp。"
                "MRS 的 domain behavior "
                "不承载这些规则，本次不会错误地写入 "
                "domain MRS。"
            )

        # ====================================================
        # 1. Domain MRS
        # ====================================================
        if opt_suffixes or opt_exacts:

            domain_name = (
                f"{group_name}_Domain"
            )

            tmp_domain_path = os.path.join(
                TEMP_DIR,
                f"{domain_name}.txt",
            )

            domain_count = (
                len(opt_suffixes)
                + len(opt_exacts)
            )

            with open(
                tmp_domain_path,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as f:

                # ------------------------------------------------
                # suffix
                #
                # DOMAIN-SUFFIX,example.com
                #
                # 必须生成：
                #
                #     +.example.com
                #
                # 而不是：
                #
                #     example.com
                #
                # 因为普通 example.com 在 Mihomo domain
                # ruleset 中是 exact。
                # ------------------------------------------------
                for domain in sorted(
                    opt_suffixes
                ):

                    f.write(
                        f"+.{domain}\n"
                    )

                # ------------------------------------------------
                # exact
                #
                # DOMAIN,example.com
                # full:example.com
                #
                # 生成：
                #
                #     example.com
                # ------------------------------------------------
                for domain in sorted(
                    opt_exacts
                ):

                    f.write(
                        f"{domain}\n"
                    )

            print(
                f"  📝 Domain text 已生成: "
                f"{tmp_domain_path}"
            )

            # ------------------------------------------------
            # 转换为 MRS
            # ------------------------------------------------
            if convert_to_mrs(
                tmp_domain_path,
                "text",
                "domain",
                domain_name,
            ):

                print(
                    f"  ✅ 成功构建: "
                    f"{domain_name}.mrs "
                    f"(共 {domain_count:,} 条规则)"
                )

                success_list.append(
                    (
                        f"{domain_name}.mrs",
                        "domain",
                        domain_count,
                    )
                )

        # ====================================================
        # 2. IP MRS
        # ====================================================
        #
        # IP / CIDR 不混入 behavior: domain。
        # 单独使用 behavior: ipcidr。
        # ====================================================
        if all_ipcidrs:

            ip_name = (
                f"{group_name}_IP"
            )

            tmp_ip_path = os.path.join(
                TEMP_DIR,
                f"{ip_name}.txt",
            )

            ip_count = len(
                all_ipcidrs
            )

            with open(
                tmp_ip_path,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as f:

                for ip in sorted(
                    all_ipcidrs
                ):

                    f.write(
                        f"{ip}\n"
                    )

            print(
                f"  📝 IP-CIDR text 已生成: "
                f"{tmp_ip_path}"
            )

            # ------------------------------------------------
            # 转换为 IP MRS
            # ------------------------------------------------
            if convert_to_mrs(
                tmp_ip_path,
                "text",
                "ipcidr",
                ip_name,
            ):

                print(
                    f"  ✅ 成功构建: "
                    f"{ip_name}.mrs "
                    f"(共 {ip_count:,} 条规则)"
                )

                success_list.append(
                    (
                        f"{ip_name}.mrs",
                        "ipcidr",
                        ip_count,
                    )
                )

    # ========================================================
    # 更新 README
    # ========================================================
    update_readme(
        success_list
    )


if __name__ == "__main__":
    main()
