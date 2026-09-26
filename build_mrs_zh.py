import os
import re
import time
import datetime
import urllib.request
import subprocess
from pathlib import Path

# ================= 扩展性配置区 =================
RULE_GROUPS = {
    "Reject_Ads": [
        "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/ruleset.yaml",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml"
        # 可添加更多广告规则链接进行合并
    ],
    "Direct_CN": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml"
    ],
    "Proxy_Global": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml"
    ]
}

OUTPUT_DIR = "mrs_rules_ZH"
# 将 TEMP 文件夹建在 OUTPUT_DIR 内部
TEMP_DIR = os.path.join(OUTPUT_DIR, "TEMP")
README_FILE = "README.md"

def setup_dirs():
    """初始化目录"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

def is_ip_or_cidr(val: str) -> bool:
    """验证字符串是否为合法的 IP 或 CIDR"""
    # 匹配 IPv4 (例如: 1.1.1.1 或 10.0.0.0/8)
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', val):
        return True
    # 匹配 IPv6 (例如: 2001:db8:: 或 2001:db8::/32)
    if ':' in val and re.match(r'^[a-fA-F0-9:]+(/\d{1,3})?$', val):
        return True
    return False

def parse_rules_from_content(content: str):
    """
    根据域名层级规则与格式提取数据：
    1. '+.A.B' / 'DOMAIN-SUFFIX' -> suffixes (后缀)
    2. 'C.D' / 'DOMAIN' -> exacts (精确)
    3. IP地址 / 'IP-CIDR' -> ipcidrs (IP段)
    """
    suffixes = set()
    exacts = set()
    ipcidrs = set()
    others = set()
    
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line == 'payload:':
            continue
            
        # 剥离 YAML 列表符号及引号
        if line.startswith('-'):
            line = line[1:].strip()
        if (line.startswith("'") and line.endswith("'")) or \
           (line.startswith('"') and line.endswith('"')):
            line = line[1:-1].strip()
            
        rule_str = line.lower()
        if not rule_str:
            continue
            
        # 场景 A: Classical 格式 (包含 ',' 或 ':')
        if ',' in rule_str or (':' in rule_str and not rule_str.startswith(('full:', 'keyword:', 'regexp:')) and not is_ip_or_cidr(rule_str)):
            sep = ',' if ',' in rule_str else ':'
            parts = [p.strip() for p in rule_str.split(sep, 2)]
            rule_type = parts[0]
            if len(parts) >= 2:
                val = parts[1]
                if rule_type == 'domain-suffix':
                    suffixes.add(val.lstrip('.'))
                elif rule_type == 'domain':
                    exacts.add(val.lstrip('.'))
                elif rule_type in ('ip-cidr', 'ip-cidr6', 'src-ip-cidr'):
                    ipcidrs.add(val)
                elif rule_type == 'domain-keyword':
                    others.add(f"keyword:{val}")
                elif rule_type == 'domain-regex':
                    others.add(f"regexp:{val}")
                    
        # 场景 B: Domain 格式与纯文本
        else:
            if rule_str.startswith('full:'):
                exacts.add(rule_str[5:].lstrip('.'))
            elif rule_str.startswith('keyword:') or rule_str.startswith('regexp:'):
                others.add(rule_str)
            elif rule_str.startswith('+.'):
                suffixes.add(rule_str[2:])
            elif is_ip_or_cidr(rule_str):
                ipcidrs.add(rule_str)
            else:
                # 无前缀字符串等同于 domain:C.D，走 exacts 提取
                exacts.add(rule_str.lstrip('.'))
                
    return suffixes, exacts, ipcidrs, others

def deduplicate_domains(suffixes: set, exacts: set):
    """根据包含关系去重，返回优化后的集合"""
    sorted_suffixes = sorted(list(suffixes), key=lambda x: x.count('.'))
    optimized_suffixes = set()
    
    # 1. 泛域名内部层级合并
    for domain in sorted_suffixes:
        parts = domain.split('.')
        is_redundant = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent.count('.') < 1: # 防御：跳过单级顶级域名
                continue
            if parent in optimized_suffixes:
                is_redundant = True
                break
        if not is_redundant:
            optimized_suffixes.add(domain)
            
    # 2. 精确域名如果存在泛域名母体，则剔除
    optimized_exacts = set()
    for domain in exacts:
        parts = domain.split('.')
        is_redundant = False
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent.count('.') < 1:
                continue
            if parent in optimized_suffixes:
                is_redundant = True
                break
        if not is_redundant:
            optimized_exacts.add(domain)
            
    return optimized_suffixes, optimized_exacts

def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str) -> bool:
    """执行 mihomo 命令行转换"""
    out_file = os.path.join(OUTPUT_DIR, f"{output_name}.mrs")
    if os.path.exists(out_file):
        try:
            os.remove(out_file)
        except OSError:
            pass
            
    cmd = ["mihomo", "convert-ruleset", behavior_type, format_type, src_path, out_file]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 转换失败: {output_name}\n{e.stderr.decode('utf-8')}")
        return False
    except FileNotFoundError:
        print("❌ 未找到 mihomo 命令，请确认环境变量。")
        return False

def update_readme(success_files):
    if not success_files:
        return
        
    repo = os.environ.get("GITHUB_REPOSITORY", "your-username/your-repo")
    branch = "main"
    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    now_str = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")
    
    md_content = f"\n### 📦 自动生成的 MRS 规则集订阅链接 (ZH)\n\n> ⏱ **最后同步时间**：`{now_str}` (UTC+8)\n\n"
    md_content += "| 文件名 | 规则类型 (Behavior) | 下载链接 |\n"
    md_content += "| :--- | :---: | :--- |\n"
    
    success_files.sort(key=lambda x: x[0])
    for filename, behavior in success_files:
        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{OUTPUT_DIR}/{filename}"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{repo}@{branch}/{OUTPUT_DIR}/{filename}"
        links = f"[GitHub Raw]({raw_url}) <br> [jsDelivr CDN]({cdn_url})"
        md_content += f"| **{filename}** | `{behavior}` | {links} |\n"
        
    if not os.path.exists(README_FILE):
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write("# 规则集订阅列表\n\n## 基础规则\n<!-- RULES_START -->\n<!-- RULES_END -->\n\n## 合并与去重规则 (ZH)\n<!-- RULES_ZH_START -->\n<!-- RULES_ZH_END -->\n")

    with open(README_FILE, "r", encoding="utf-8") as f:
        readme_content = f.read()

    pattern = re.compile(r'<!-- RULES_ZH_START -->.*<!-- RULES_ZH_END -->', re.DOTALL)
    if pattern.search(readme_content):
        new_content = pattern.sub(f'<!-- RULES_ZH_START -->\n{md_content}\n<!-- RULES_ZH_END -->', readme_content)
    else:
        new_content = readme_content + f"\n\n<!-- RULES_ZH_START -->\n{md_content}\n<!-- RULES_ZH_END -->"

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)

def main():
    setup_dirs()
    success_list = []
    
    for group_name, urls in RULE_GROUPS.items():
        print(f"\n🔄 正在处理规则组: {group_name} ...")
        all_suffixes, all_exacts, all_ipcidrs, all_others = set(), set(), set(), set()
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    content = response.read().decode('utf-8')
                suffs, exts, ips, oths = parse_rules_from_content(content)
                all_suffixes.update(suffs)
                all_exacts.update(exts)
                all_ipcidrs.update(ips)
                all_others.update(oths)
            except Exception as e:
                print(f"  ❌ 下载或解析失败 {url}: {e}")
                
        if not any([all_suffixes, all_exacts, all_ipcidrs, all_others]):
            continue
            
        print(f"  🧹 开始域名去重。合并前域名数: {len(all_suffixes) + len(all_exacts)}")
        opt_suffixes, opt_exacts = deduplicate_domains(all_suffixes, all_exacts)
        print(f"  ✨ 去重完成，优化后域名数: {len(opt_suffixes) + len(opt_exacts)}")
        
        # =============== 1. 生成并转换 Domain 规则文件 ===============
        has_domain_rules = bool(opt_suffixes or opt_exacts or all_others)
        if has_domain_rules:
            domain_name = f"{group_name}_Domain"
            tmp_domain_path = os.path.join(TEMP_DIR, f"{domain_name}.txt")
            
            with open(tmp_domain_path, 'w', encoding='utf-8') as f:
                for s in sorted(opt_suffixes):
                    f.write(f"{s}\n")
                for e in sorted(opt_exacts):
                    f.write(f"full:{e}\n")
                for o in sorted(all_others):
                    f.write(f"{o}\n")
                    
            if convert_to_mrs(tmp_domain_path, "text", "domain", domain_name):
                print(f"  ✅ 成功构建: {domain_name}.mrs")
                success_list.append((f"{domain_name}.mrs", "domain"))
                
        # =============== 2. 生成并转换 IP 规则文件 ===============
        if all_ipcidrs:
            ip_name = f"{group_name}_IP"
            tmp_ip_path = os.path.join(TEMP_DIR, f"{ip_name}.txt")
            
            with open(tmp_ip_path, 'w', encoding='utf-8') as f:
                for ip in sorted(all_ipcidrs):
                    f.write(f"{ip}\n")
                    
            if convert_to_mrs(tmp_ip_path, "text", "ipcidr", ip_name):
                print(f"  ✅ 成功构建: {ip_name}.mrs")
                success_list.append((f"{ip_name}.mrs", "ipcidr"))
                
    update_readme(success_list)

if __name__ == "__main__":
    main()
