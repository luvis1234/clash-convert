import urllib.request
import os
import re
from datetime import datetime, timezone

# --- 配置区 ---
SOURCE_URLS = [
    ##源文件网址之间用,隔开，最后一个不加
    # "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt"
    https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt
]

LOCAL_FILES = ["data.txt"]
OUTPUT_FILE = "ruleset.yaml"
README_FILE = "README.md"  # <--- 之前报错是因为这里可能缺失或拼写错误
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

def main():
    all_domains = set()

    # 1. 抓取与合并
    for source in SOURCE_URLS + LOCAL_FILES:
        lines = fetch_content(source)
        for line in lines:
            domain = clean_domain(line)
            if domain:
                all_domains.add(domain)

    sorted_domains = sorted(list(all_domains))
    
    # 2. 获取当前 UTC 时间 (使用推荐的新方法)
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # 3. 写入 ruleset.yaml
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Update Time: {now_utc}\n")
        f.write(f"# Total Domains: {len(sorted_domains)}\n\n")
        f.write("payload:\n")
        for domain in sorted_domains:
            f.write(f"  - '{domain}'\n")
    
    # 4. 自动更新 README.md
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



