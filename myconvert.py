import urllib.request
import os
import re
from datetime import datetime, timezone

# --- 配置区 ---
# 1. 明确声明为 Clash 混合规则的源 (支持自动识别其中混杂的泛域名和纯域名)
CLASH_WILDCARD_SOURCES = [
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.yaml"
    
    #"https://github.com/luvis1234/tracker/blob/main/antiad.yaml"
    # "https://example.com/clash_myad.yaml",
    # "clash规则格式.yaml",
]

# 2. 纯域名格式的源文件 (如果有误入的泛域名格式也能自动识别)
PLAIN_DOMAIN_SOURCES = [
    "data.txt",
]

OUTPUT_FILE = "myad.txt"
README_FILE = "README.md"
# --- --- --- ---

def fetch_content(source):
    lines = []
    try:
        if source.startswith("http"):
            req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                lines = response.read().decode('utf-8').splitlines()
        elif os.path.exists(source):
            with open(source, 'r', encoding='utf-8') as f:
                lines = f.readlines()
    except Exception as e:
        print(f"⚠️ 读取源失败 {source}: {e}")
        return []

    # 跳过文件开头所有以 '#' 开头的注释行及空白说明行
    start_idx = 0
    while start_idx < len(lines):
        stripped = lines[start_idx].strip()
        if stripped.startswith('#') or not stripped:
            start_idx += 1
        else:
            break
    return lines[start_idx:]

def clean_domain(line):
    """
    解析并清洗域名，返回：(干净的域名小写字符串, 是否为泛域名布尔值)
    """
    line = line.strip()
    if not line or any(line.startswith(x) for x in ['#', '//', '!', 'payload:', '...']):
        return None, False
    
    # 移除 YAML 列表符号、引号
    domain = re.sub(r'^-\s+', '', line).replace("'", "").replace('"', '')
    
    is_wildcard = False
    # 判断是否带有泛域名特征的符号 (+. / *. / .)
    if re.search(r'^(\+\.|\*\.|\.)', domain):
        is_wildcard = True
        domain = re.sub(r'^(\+\.|\*\.|\.)', '', domain)
    
    if ',' in domain:
        parts = domain.split(',')
        if len(parts) >= 2:
            domain = parts[1].strip()

    return domain.lower() if domain else None, is_wildcard

def filter_subdomains(domains):
    """
    针对泛域名集合进行向上溯源去重：保留最高级父域名
    """
    domains_sorted = sorted(list(domains), key=len)
    root_domains = set()
    
    for domain in domains_sorted:
        parts = domain.split('.')
        is_subdomain = False
        
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in root_domains:
                is_subdomain = True
                break
        
        if not is_subdomain:
            root_domains.add(domain)
            
    return root_domains

def is_covered_by_wildcards(domain, wildcard_roots):
    """
    检查某个纯域名是否已经被最高级泛域名库覆盖拦截：
    如果泛域名库里有 example.com，那 example.com 和 a.example.com 都视为被覆盖
    """
    if domain in wildcard_roots:
        return True
        
    parts = domain.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in wildcard_roots:
            return True
    return False

def main():
    # 汇总保存所有源中的泛域名与纯域名
    all_raw_wildcards = set()
    all_raw_plains = set()

    # 1. 抓取 Clash 规则源并直接加入合并池
    for source in CLASH_WILDCARD_SOURCES:
        for line in fetch_content(source):
            domain, is_wildcard = clean_domain(line)
            if domain:
                if is_wildcard:
                    all_raw_wildcards.add(domain)
                else:
                    all_raw_plains.add(domain)

    # 2. 抓取纯域名源并直接加入合并池
    for source in PLAIN_DOMAIN_SOURCES:
        for line in fetch_content(source):
            domain, is_wildcard = clean_domain(line)
            if domain:
                if is_wildcard:
                    all_raw_wildcards.add(domain)
                else:
                    all_raw_plains.add(domain)

    # 3. 对合并后的泛域名进行向上溯源归并（消除子域名冗余，保留最高级父域）
    final_base_wildcards = filter_subdomains(all_raw_wildcards)
    
    # 4. 对合并后的纯域名进行过滤：如果已被泛域名覆盖则剔除，避免重复
    final_plain_domains = set()
    for domain in all_raw_plains:
        if not is_covered_by_wildcards(domain, final_base_wildcards):
            final_plain_domains.add(domain)

    # 5. 格式化并生成统一的输出列表
    output_lines = []
    
    # 仅原本就是泛域名的条目加上 "." 前缀
    for domain in final_base_wildcards:
        output_lines.append(f".{domain}")
        
    # 纯域名直接保留原样，不加前缀
    for domain in final_plain_domains:
        output_lines.append(domain)

    # 按字母表顺序排序
    output_lines.sort()
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # 6. 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Update Time: {now_utc}\n")
        f.write(f"# Total Domains: {len(output_lines)}\n\n")
        for line in output_lines:
            f.write(line + "\n")
    
    # 7. 自动更新 README.md
    if os.path.exists(README_FILE):
        with open(README_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        
        content = re.sub(r"当前规则总数：.*", f"当前规则总数：`{len(output_lines)}`", content)
        content = re.sub(r"最后更新时间：.*", f"最后更新时间：`{now_utc}`", content)
        
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        print("✅ README 统计信息已更新")
    
    print(f"✅ 处理完成，成功合并去重并生成最终规则数: {len(output_lines)} 条")

if __name__ == '__main__':
    main()
