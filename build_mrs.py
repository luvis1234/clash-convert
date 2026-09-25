import os
import re
import time
import datetime
import urllib.request
import subprocess
import yaml
from pathlib import Path

RULE_URLS = [
    # 替换为你真实的规则链接
    "https://raw.githubusercontent.com/luvis1234/clash-convert/refs/heads/main/ruleset.yaml",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.yaml"
]

OUTPUT_DIR = "mrs_rules_sp"
TEMP_DIR = ".tmp_rules"
README_FILE = "README.md"

def setup_dirs():
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

def analyze_content(content: str) -> tuple:
    fmt = "text"
    behavior = "unknown"
    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
    
    if not lines:
        return fmt, behavior

    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'payload' in data:
            fmt = "yaml"
            lines = data['payload']
    except yaml.YAMLError:
        pass

    sample_size = min(len(lines), 20)
    samples = lines[:sample_size]
    classical_keywords = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'IP-CIDR,', 'GEOIP,', 'MATCH')
    
    for item in samples:
        item_str = str(item).strip()
        if any(item_str.startswith(k) for k in classical_keywords):
            return fmt, "classical"
        if re.search(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', item_str) or re.search(r'^[a-fA-F0-9:]+/\d{1,3}$', item_str):
            behavior = "ipcidr"
        if item_str.startswith(('full:', 'keyword:', 'regexp:')) or re.match(r'^[a-zA-Z0-9\-\.\*]+$', item_str):
            if behavior != "ipcidr":
                behavior = "domain"

    return fmt, behavior

def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str) -> bool:
    if behavior_type == "classical":
        print(f"⚠️ 跳过 {output_name}：mrs 格式暂不支持 classical behavior。")
        return False
        
    out_file = os.path.join(OUTPUT_DIR, f"{output_name}.mrs")
    
    # 转换前清理旧文件，防止覆盖失败
    if os.path.exists(out_file):
        try:
            os.remove(out_file)
        except OSError as e:
            print(f"⚠️ 无法删除旧文件 {out_file}: {e}")
            
    cmd = ["mihomo", "convert-ruleset", behavior_type, format_type, src_path, out_file]
    
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"✅ 转换成功: {out_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 转换失败: {output_name}\n{e.stderr.decode('utf-8')}")
        return False
    except FileNotFoundError:
        print("❌ 未找到 mihomo 命令")
        return False

def update_readme(success_files):
    if not success_files:
        print("没有成功转换的文件，跳过更新 README。")
        return
        
    repo = os.environ.get("GITHUB_REPOSITORY", "your-username/your-repo")
    branch = "main"
    
    # 获取东八区当前时间
    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    now_str = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")
    
    md_content = f"\n### 📦 自动生成的 MRS 规则集订阅链接\n\n> ⏱ **最后同步时间**：`{now_str}` (UTC+8)\n\n你可以直接在 Mihomo 配置文件中引用以下链接：\n\n"
    
    for file, behavior in success_files:
        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{OUTPUT_DIR}/{file}"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{repo}@{branch}/{OUTPUT_DIR}/{file}"
        
        md_content += f"- **{file}** (Behavior: `{behavior}`)\n"
        md_content += f"  - GitHub Raw: `{raw_url}`\n"
        md_content += f"  - jsDelivr CDN (推荐): `{cdn_url}`\n\n"
        
    if not os.path.exists(README_FILE):
        print(f"未找到 {README_FILE}，将自动创建。")
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(f"# 规则集\n\n<!-- RULES_START -->\n<!-- RULES_END -->\n")

    with open(README_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(r'<!-- RULES_START -->.*<!-- RULES_END -->', re.DOTALL)
    if pattern.search(content):
        new_content = pattern.sub(f'<!-- RULES_START -->\n{md_content}<!-- RULES_END -->', content)
    else:
        new_content = content + f"\n\n<!-- RULES_START -->\n{md_content}<!-- RULES_END -->"

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("✅ README.md 订阅链接已成功更新。")

def main():
    setup_dirs()
    success_list = []
    
    for url in RULE_URLS:
        filename = url.split('/')[-1]
        base_name = os.path.splitext(filename)[0]
        tmp_path = os.path.join(TEMP_DIR, filename)
        
        # 添加时间戳参数，强制跳过 GitHub Raw CDN 缓存
        timestamp = int(time.time())
        fetch_url = f"{url}?t={timestamp}"
        
        try:
            req = urllib.request.Request(fetch_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                with open(tmp_path, 'wb') as f:
                    f.write(response.read())
        except Exception as e:
            print(f"❌ 下载失败 {url}: {e}")
            continue
            
        # 安全读取文件，防止句柄占用导致转换失败
        with open(tmp_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        fmt, behavior = analyze_content(content)
        
        if behavior != "unknown":
            if convert_to_mrs(tmp_path, fmt, behavior, base_name):
                success_list.append((f"{base_name}.mrs", behavior))
                
    update_readme(success_list)

if __name__ == "__main__":
    main()
