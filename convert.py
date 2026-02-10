import urllib.request
import os
import re
from datetime import datetime

# --- 配置区 ---
# 远程源列表
SOURCE_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt", # 规则集格式示例
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Classical_No_Resolve.yaml", 
	"https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockmihomo.yaml"# 纯域名格式示例
]

# 本地源文件 (在你的仓库根目录下创建一个 data.txt)
LOCAL_FILES = ["data.txt"]

# 输出文件名
OUTPUT_FILE = "antiad.yaml"
# --- --- --- ---

def fetch_content(source):
    """获取内容，支持 http 和本地文件"""
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

def parse_rule(line):
    """
    核心解析逻辑：
    1. 纯域名 -> DOMAIN (精确匹配，防误杀)
    2. 已有格式 -> 保持原样 (DOMAIN-SUFFIX, IP-CIDR 等)
    3. 纯 IP -> IP-CIDR
    """
    line = line.strip()
    # 过滤注释、空行、YAML 声明
    if not line or any(line.startswith(x) for x in ['#', '//', '!', 'payload:', '...']):
        return None
    
    # 清洗：移除 YAML 横杠和引号
    line = re.sub(r'^-\s+', '', line)
    line = line.replace("'", "").replace('"', '')

    # 情况 A：已经是标准规则格式 (包含逗号)
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 2:
            return f"{parts[0].upper()},{parts[1].lower()}"

    # 情况 B：纯域名或纯 IP
    clean_val = line.lstrip('.')
    if '.' in clean_val and ' ' not in clean_val:
        # 识别 IP 地址 (IPv4 格式)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', clean_val):
            return f"IP-CIDR,{clean_val}"
        # 纯域名 -> 转换为 DOMAIN
        return f"DOMAIN,{clean_val.lower()}"

    return None

def main():
    all_rules = set()

    for source in SOURCE_URLS + LOCAL_FILES:
        lines = fetch_content(source)
        for line in lines:
            rule = parse_rule(line)
            if rule:
                all_rules.add(rule)

    sorted_rules = sorted(list(all_rules))
    # 记录 UTC 时间以便核对更新状态
    now_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# --------------------------------------------------------------\n")
        f.write(f"# Update Time: {now_utc}\n")
        f.write(f"# Total Rules: {len(sorted_rules)}\n")
        f.write(f"# Note: Raw domains were converted to DOMAIN for precision.\n")
        f.write(f"# --------------------------------------------------------------\n\n")
        f.write("payload:\n")
        for rule in sorted_rules:
            f.write(f"  - {rule}\n")
    
    print(f"✅ 处理完成，共生成 {len(sorted_rules)} 条规则。")

if __name__ == '__main__':

    main()
