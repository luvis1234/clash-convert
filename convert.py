import urllib.request
import os
import re
from datetime import datetime

# --- 配置区 ---
# 远程源列表
SOURCE_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt"# 纯域名格式示例
]

# 本地源文件 (在你的仓库根目录下创建一个 data.txt)
LOCAL_FILES = ["data.txt"]

# 输出文件名
OUTPUT_FILE = "antiad.yaml"
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
    """
    极简清洗：只处理域名字符串
    """
    line = line.strip()
    # 过滤掉空行、注释、以及 YAML 标记
    if not line or any(line.startswith(x) for x in ['#', '//', '!', 'payload:', '...']):
        return None
    
    # 移除 YAML 列表符号和引号，以及前导的点
    domain = re.sub(r'^-\s+', '', line).replace("'", "").replace('"', '').lstrip('.')
    
    # 基本校验：确保不是空白
    return domain.lower() if domain else None

def main():
    all_domains = set()

    # 1. 直接提取并去重
    for source in SOURCE_URLS + LOCAL_FILES:
        lines = fetch_content(source)
        for line in lines:
            domain = clean_domain(line)
            if domain:
                all_domains.add(domain)

    sorted_domains = sorted(list(all_domains))
    now_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    # 2. 写入 ruleset.yaml (Domain 格式)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Update Time: {now_utc}\n")
        f.write(f"# Total Domains: {len(sorted_domains)}\n\n")
        f.write("payload:\n")
        for domain in sorted_domains:
            # 使用 '.domain' 格式以匹配子域名
            f.write(f"  - '.{domain}'\n")
    
    # 3. 自动同步到 README.md
    if os.path.exists(README_FILE):
        with open(README_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        content = re.sub(r"当前规则总数：.*", f"当前规则总数：`{len(sorted_domains)}`", content)
        content = re.sub(r"最后更新时间：.*", f"最后更新时间：`{now_utc}`", content)
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        print("✅ README 已同步")
    
    print(f"✅ 转换完成，共生成 {len(sorted_domains)} 条域名规则。")

if __name__ == '__main__':
    main()



