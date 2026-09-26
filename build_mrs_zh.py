import os
import re
import time
import datetime
import urllib.request
import subprocess
import yaml
from pathlib import Path

# ================= 扩展性配置区 =================
# 以字典形式配置不同的规则组，字典的 Key 将作为生成的 mrs 文件名
RULE_GROUPS = {
    "Reject_Ads": [
        # 在这里填入广告拦截相关的 yaml (domain 或 classical 格式均可)
        "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/ruleset.yaml",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml",
        # 可添加更多广告规则链接进行合并
    ],
    "Direct_CN": [
        # 在这里填入国内直连相关的 yaml
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml"
    ],
    "Proxy_Global": [
        # 在这里填入需要走代理的全局域名 yaml
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml"
    ]
}

OUTPUT_DIR = "mrs_rules_ZH"
TEMP_DIR = ".tmp_rules"
README_FILE = "README.md"

def setup_dirs():
    """初始化目录"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

def parse_domains_from_content(content: str):
    """
    解析文件内容，兼容 classical 和 domain 的 yaml 格式，提取域名
    返回: (suffixes 集合, exacts 集合, others 集合)
    """
    suffixes = set()
    exacts = set()
    others = set()
    
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or 'payload' not in data:
            return suffixes, exacts, others
        rules = data['payload']
    except yaml.YAMLError:
        return suffixes, exacts, others

    for rule in rules:
        rule_str = str(rule).strip()
        if not rule_str or rule_str.startswith('#'):
            continue
            
        # 识别 classical 格式
        if ',' in rule_str and rule_str.upper().startswith(('DOMAIN', 'IP-', 'SRC-', 'DST-', 'PROCESS-', 'GEO', 'MATCH')):
            parts = [p.strip() for p in rule_str.split(',', 2)]
            rule_type = parts[0].upper()
            if len(parts) >= 2:
                val = parts[1]
                if rule_type == 'DOMAIN-SUFFIX':
                    suffixes.add(val)
                elif rule_type == 'DOMAIN':
                    exacts.add(val)
                elif rule_type == 'DOMAIN-KEYWORD':
                    others.add(f"keyword:{val}")
                elif rule_type == 'DOMAIN-REGEX':
                    others.add(f"regexp:{val}")
                
        # 识别 domain yaml 格式
        else:
            if rule_str.startswith('full:'):
                exacts.add(rule_str[5:])
            elif rule_str.startswith('keyword:') or rule_str.startswith('regexp:'):
                others.add(rule_str)
            elif rule_str.startswith('+.'):
                suffixes.add(rule_str[2:])
            else:
                suffixes.add(rule_str)
                
    return suffixes, exacts, others

def deduplicate_domains(suffixes: set, exacts: set):
    """根据域名级别进行去重合并"""
    sorted_suffixes = sorted(list(suffixes), key=lambda x: x.count('.'))
    optimized_suffixes = set()
    
    for domain in sorted_suffixes:
        parts = domain.split('.')
        is_redundant = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in optimized_suffixes:
                is_redundant = True
                break
        if not is_redundant:
            optimized_suffixes.add(domain)
            
    optimized_exacts = set()
    for domain in exacts:
        parts = domain.split('.')
        is_redundant = False
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in optimized_suffixes:
                is_redundant = True
                break
        if not is_redundant:
            optimized_exacts.add(domain)
            
    return optimized_suffixes, optimized_exacts

def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str) -> bool:
    """调用 mihomo 转换为 mrs 格式"""
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
    """
    更新 README 订阅链接
    表格三列展示：文件名 | 格式 | 下载链接
    """
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
        
    # 【修改点 1】：如果文件不存在，初始化时同时写入两组标签，方便后续两个脚本都能找到各自的替换区
    if not os.path.exists(README_FILE):
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write("# 规则集订阅列表\n\n## 基础规则\n<!-- RULES_START -->\n<!-- RULES_END -->\n\n## 合并与去重规则 (ZH)\n<!-- RULES_ZH_START -->\n<!-- RULES_ZH_END -->\n")

    with open(README_FILE, "r", encoding="utf-8") as f:
        readme_content = f.read()

    # 【修改点 2】：正则匹配替换为 RULES_ZH_START 和 RULES_ZH_END
    pattern = re.compile(r'<!-- RULES_ZH_START -->.*<!-- RULES_ZH_END -->', re.DOTALL)
    if pattern.search(readme_content):
        new_content = pattern.sub(f'<!-- RULES_ZH_START -->\n{md_content}\n<!-- RULES_ZH_END -->', readme_content)
    else:
        # 如果文件中没有 ZH 标签，则在文件末尾追加
        new_content = readme_content + f"\n\n<!-- RULES_ZH_START -->\n{md_content}\n<!-- RULES_ZH_END -->"

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("✅ README.md 订阅链接表格已成功更新 (ZH区)。")

def main():
    setup_dirs()
    success_list = []
    
    for group_name, urls in RULE_GROUPS.items():
        print(f"🔄 正在处理规则组: {group_name} ...")
        
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
            
        print(f"  🧹 提取完成，开始去重。合并前规则数: {len(all_suffixes) + len(all_exacts)}")
        opt_suffixes, opt_exacts = deduplicate_domains(all_suffixes, all_exacts)
        print(f"  ✨ 去重完成，优化后规则数: {len(opt_suffixes) + len(opt_exacts)}")
        
        tmp_path = os.path.join(TEMP_DIR, f"{group_name}.txt")
        with open(tmp_path, 'w', encoding='utf-8') as f:
            for s in sorted(opt_suffixes):
                f.write(f"{s}\n")
            for e in sorted(opt_exacts):
                f.write(f"full:{e}\n")
            for o in sorted(all_others):
                f.write(f"{o}\n")
                
        # 转换为 mrs
        if convert_to_mrs(tmp_path, "text", "domain", group_name):
            # 将 (文件名, 格式) 记录到成功列表中
            success_list.append((f"{group_name}.mrs", "mrs"))
            
    update_readme(success_list)

if __name__ == "__main__":
    main()
