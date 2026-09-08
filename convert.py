import urllib.request
import os
import re
from datetime import datetime, timezone

# --- 配置区 ---
SOURCE_URLS = [
   "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate.mini-onlydomains.txt",
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
   "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt"
]

LOCAL_FILES = ["data.txt"]
OUTPUT_FILE = "ruleset.yaml"
README_FILE = "README.md"
# --- --- --- ---

def fetch_content(source):
    try:
        if source.startswith("http"):
            req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.read().decode('utf-8').splitlines()
        elif os.path.exists(source):
            with open(source, 'r', encoding='utf-8') as f:
                return f.readlines()
    except Exception as e:
        print(f"⚠️ 读取源失败 {source}: {e}")
    return []

def clean_domain(line):
    line = line.strip()
    if not line or any(line.startswith(x) for x in ['#', '//', '!', 'payload:', '...']):
        return None
    
    # 移除 YAML 列表符号、引号，以及前导点
    domain = re.sub(r'^-\s+', '', line).replace("'", "").replace('"', '').lstrip('.')
    
    # 如果源文件是 Classical 格式 (TYPE,VALUE)，提取 VALUE
    if ',' in domain:
        parts = domain.split(',')
        if len(parts) >= 2:
            domain = parts[1].strip()

    return domain.lower() if domain else None

def filter_subdomains(domains):
    """
    根据域名级别去重，将子域名合并到上级域名。
    """
    # 按长度升序排序，确保上级域名（较短）先被处理存入 set 中
    domains_sorted = sorted(list(domains), key=len)
    root_domains = set()
    
    for domain in domains_sorted:
        parts = domain.split('.')
        is_subdomain = False
        
        # 逐级切分向上查找。例如对于 "a.b.com"，循环验证 "b.com" 和 "com" 是否已存在
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in root_domains:
                is_subdomain = True
                break
        
        if not is_subdomain:
            root_domains.add(domain)
            
    return root_domains

def main():
    all_domains = set()

    # 1. 抓取与合并
    for source in SOURCE_URLS + LOCAL_FILES:
        lines = fetch_content(source)
        for line in lines:
            domain = clean_domain(line)
            if domain:
                all_domains.add(domain)

    # 2. 执行层级去重，并按照字母表顺序排序以输出
    optimized_domains = filter_subdomains(all_domains)
    sorted_domains = sorted(list(optimized_domains))
    
    # 3. 获取当前 UTC 时间
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # 4. 写入 ruleset.yaml
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Update Time: {now_utc}\n")
        f.write(f"# Total Domains: {len(sorted_domains)}\n\n")
        f.write("payload:\n")
        for domain in sorted_domains:
            f.write(f"  - '{domain}'\n")
    
    # 5. 自动更新 README.md
    if os.path.exists(README_FILE):
        with open(README_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 替换统计信息
        content = re.sub(r"当前规则总数：.*", f"当前规则总数：`{len(sorted_domains)}`", content)
        content = re.sub(r"最后更新时间：.*", f"最后更新时间：`{now_utc}`", content)
        
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        print("✅ README 统计信息已更新")
    
    print(f"✅ 处理完成，共生成 {len(sorted_domains)} 条域名规则。")

if __name__ == '__main__':
    main()
