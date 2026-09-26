import os
import re
import time
import datetime
import urllib.request
import subprocess
import yaml
from pathlib import Path

RULE_GROUPS = {
    "Reject_Ads": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml",
        # 此处替换为 adblockmihomo.yaml 等其他广告规则链接
    ],
    "Direct_CN": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml"
    ],
    "Proxy_Global": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml"
    ]
}

OUTPUT_DIR = "mrs_rules_ZH"
TEMP_DIR = ".tmp_rules"
README_FILE = "README.md"

def setup_dirs():
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

def parse_domains_from_content(content: str):
    suffixes = set()
    exacts = set()
    others = set()
    rules = []
    
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'payload' in data:
            rules = data['payload']
        elif isinstance(data, list):
            rules = data
        else:
            rules = content.split('\n')
    except yaml.YAMLError:
        rules = content.split('\n')

    for rule in rules:
        rule_str = str(rule).strip().lower()
        if not rule_str or rule_str.startswith('#'):
            continue
            
        if ',' in rule_str and rule_str.startswith(('domain', 'ip-', 'src-', 'dst-', 'process-', 'geo', 'match')):
            parts = [p.strip() for p in rule_str.split(',', 2)]
            rule_type = parts[0]
            if len(parts) >= 2:
                val = parts[1]
                if rule_type == 'domain-suffix':
                    suffixes.add(val.lstrip('.'))
                elif rule_type == 'domain':
                    exacts.add(val)
                elif rule_type == 'domain-keyword':
                    others.add(f"keyword:{val}")
                elif rule_type == 'domain-regex':
                    others.add(f"regexp:{val}")
        else:
            if rule_str.startswith('full:'):
                exacts.add(rule_str[5:])
            elif rule_str.startswith('keyword:') or rule_str.startswith('regexp:'):
                others.add(rule_str)
            elif rule_str.startswith('+.'):
                suffixes.add(rule_str[2:])
            elif re.match(r'^[\d\.]+$', rule_str) or (':' in rule_str and rule_str.replace(':', '').isalnum()):
                # 修复2：如果直接是纯IP地址，强制作为 exacts (转换为 full:10.10.x.x)，避免被错误处理为 suffix
                exacts.add(rule_str)
            else:
                suffixes.add(rule_str.lstrip('.'))
                
    return suffixes, exacts, others

def deduplicate_domains(suffixes: set, exacts: set):
    sorted_suffixes = sorted(list(suffixes), key=lambda x: x.count('.'))
    optimized_suffixes = set()
    removed_logs = []
    
    # 优化 suffixes
    for domain in sorted_suffixes:
        parts = domain.split('.')
        is_redundant = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            
            # 修复1：禁止使用顶级域名（如 .ru, .com, 0个点）作为基准进行去重，防止上游误杀
            if parent.count('.') < 1:
                continue
                
            if parent in optimized_suffixes:
                is_redundant = True
                removed_logs.append(f"[Suffix 去重] {domain} -> 已被宽泛规则涵盖: {parent}")
                break
                
        if not is_redundant:
            optimized_suffixes.add(domain)
            
    # 优化 exacts
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
                removed_logs.append(f"[Exact 去重] {domain} -> 已被泛域名涵盖: {parent}")
                break
                
        if not is_redundant:
            optimized_exacts.add(domain)
            
    return optimized_suffixes, optimized_exacts, removed_logs

def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str) -> bool:
    out_file = os.path.join(OUTPUT_DIR, f"{output_name}.mrs")
    if os.path.exists(out_file):
        try:
            os.remove(out_file)
        except OSError:
            pass
            
    cmd = ["mihomo", "convert-ruleset", behavior_type, format_type, src_path, out_file]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"✅ 转换成功: {out_file} (Behavior: {behavior_type})")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 转换失败: {output_name}\n{e.stderr.decode('utf-8')}")
        return False
    except FileNotFoundError:
        print("❌ 未找到 mihomo 命令")
        return False

def update_readme(success_files):
    if not success_files:
        return
        
    repo = os.environ.get("GITHUB_REPOSITORY", "your-username/your-repo")
    branch = "main"
    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    now_str = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")
    
    md_content = f"\n### 📦 自动生成的 MRS 规则集订阅链接 (ZH)\n\n> ⏱ **最后同步时间**：`{now_str}` (UTC+8)\n\n"
    md_content += "| 文件名 | 格式 | 下载链接 |\n"
    md_content += "| :--- | :---: | :--- |\n"
    
    success_files.sort(key=lambda x: x[0])
    for filename, fmt in success_files:
        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{OUTPUT_DIR}/{filename}"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{repo}@{branch}/{OUTPUT_DIR}/{filename}"
        links = f"[GitHub Raw]({raw_url}) <br> [jsDelivr CDN]({cdn_url})"
        md_content += f"| **{filename}** | `{fmt}` | {links} |\n"
        
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
        
        all_suffixes = set()
        all_exacts = set()
        all_others = set()
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    content = response.read().decode('utf-8')
                    
                suffs, exts, oths = parse_domains_from_content(content)
                all_suffixes.update(suffs)
                all_exacts.update(exts)
                all_others.update(oths)
            except Exception as e:
                print(f"  ❌ 下载或解析失败 {url}: {e}")
                continue
                
        if not all_suffixes and not all_exacts and not all_others:
            print(f"  ⚠️ {group_name} 未提取到任何域名，跳过。")
            continue
            
        # 调试功能 1：输出合并后、去重前的全量规则
        debug_before = os.path.join(TEMP_DIR, f"{group_name}_before_dedup.txt")
        with open(debug_before, 'w', encoding='utf-8') as f:
            for item in sorted(all_suffixes | all_exacts | all_others):
                f.write(f"{item}\n")
                
        print(f"  🧹 提取完成，开始去重。合并前规则数: {len(all_suffixes) + len(all_exacts)}")
        opt_suffixes, opt_exacts, removed_logs = deduplicate_domains(all_suffixes, all_exacts)
        
        # 调试功能 2：输出去重日志，找出是谁误杀了正常域名
        debug_log = os.path.join(TEMP_DIR, f"{group_name}_removed_debug.log")
        with open(debug_log, 'w', encoding='utf-8') as f:
            f.write(f"Total Removed: {len(removed_logs)}\n\n")
            f.write("\n".join(removed_logs))
            
        print(f"  ✨ 去重完成，优化后规则数: {len(opt_suffixes) + len(opt_exacts)}")
        print(f"  🔍 去重明细请查看: {debug_log}")
        
        # 调试功能 3 / 转换输入源：输出最终精简版
        tmp_path = os.path.join(TEMP_DIR, f"{group_name}_after_dedup.txt")
        with open(tmp_path, 'w', encoding='utf-8') as f:
            for s in sorted(opt_suffixes):
                f.write(f"{s}\n")
            for e in sorted(opt_exacts):
                f.write(f"full:{e}\n")
            for o in sorted(all_others):
                f.write(f"{o}\n")
                
        if convert_to_mrs(tmp_path, "text", "domain", group_name):
            success_list.append((f"{group_name}.mrs", "mrs"))
            
    update_readme(success_list)

if __name__ == "__main__":
    main()
