import os
import re
import urllib.request
import urllib.error
import subprocess
import yaml
from pathlib import Path

# ================= 配置区域 =================
# 待下载的远程规则集 URL 列表
RULE_URLS = [
    "https://raw.githubusercontent.com/example/rules/main/domain/reject.txt",
    "https://raw.githubusercontent.com/example/rules/main/ip/telegram.yaml"
]

# 输出目录
OUTPUT_DIR = "mrs_rules_sp"
TEMP_DIR = ".tmp_rules" # 用于存放下载的源文件以便 mihomo 调用

# ================= 核心逻辑 =================

def setup_dirs():
    """初始化输出和临时目录"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

def analyze_content(content: str) -> tuple:
    """
    分析文本内容，自动识别 format 和 behavior。
    返回: (format_type, behavior_type)
    """
    fmt = "text"
    behavior = "unknown"
    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
    
    if not lines:
        return fmt, behavior

    # 1. 识别 Format: 是否为合法的 YAML 以及是否包含 payload 键
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'payload' in data:
            fmt = "yaml"
            lines = data['payload'] # 将检测目标缩小到 payload 列表
    except yaml.YAMLError:
        pass

    # 2. 识别 Behavior: 抽样检查规则条目特征
    sample_size = min(len(lines), 20)
    samples = lines[:sample_size]
    
    classical_keywords = ('DOMAIN,', 'DOMAIN-SUFFIX,', 'IP-CIDR,', 'GEOIP,', 'MATCH')
    
    for item in samples:
        item_str = str(item).strip()
        
        # 检查是否为 classical (完整规则语法)
        if any(item_str.startswith(k) for k in classical_keywords):
            return fmt, "classical"
            
        # 检查是否为 ipcidr (包含 CIDR 斜杠格式)
        if re.search(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', item_str) or re.search(r'^[a-fA-F0-9:]+/\d{1,3}$', item_str):
            behavior = "ipcidr"
            
        # 检查是否为 domain 特殊匹配前缀 (full:, keyword:, regexp:) 或纯域名
        if item_str.startswith(('full:', 'keyword:', 'regexp:')) or re.match(r'^[a-zA-Z0-9\-\.\*]+$', item_str):
            # 如果前面没有被判定为 ipcidr，则大概率是 domain
            if behavior != "ipcidr":
                behavior = "domain"

    return fmt, behavior

def convert_to_mrs(src_path: str, format_type: str, behavior_type: str, output_name: str):
    """调用 mihomo 内核进行 mrs 转换"""
    if behavior_type == "classical":
        print(f"⚠️ 跳过 {output_name}：mrs 格式暂不支持 classical behavior。")
        return False
        
    out_file = os.path.join(OUTPUT_DIR, f"{output_name}.mrs")
    
    # 构建转换命令: mihomo convert-ruleset <behavior> <format> <src> <dst>
    cmd = [
        "mihomo", 
        "convert-ruleset", 
        behavior_type, 
        format_type, 
        src_path, 
        out_file
    ]
    
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"✅ 转换成功: {out_file} (Behavior: {behavior_type}, Format: {format_type})")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 转换失败: {output_name}\n错误信息: {e.stderr.decode('utf-8')}")
        return False
    except FileNotFoundError:
        print("❌ 未找到 mihomo 命令，请确保系统 PATH 中存在 mihomo 可执行文件。")
        return False

def main():
    setup_dirs()
    
    for url in RULE_URLS:
        filename = url.split('/')[-1]
        base_name = os.path.splitext(filename)[0]
        tmp_path = os.path.join(TEMP_DIR, filename)
        
        print(f"\n⬇️ 正在下载: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content_bytes = response.read()
                content_str = content_bytes.decode('utf-8')
                
                # 保存源文件到临时目录供 mihomo 读取
                with open(tmp_path, 'wb') as f:
                    f.write(content_bytes)
                    
        except Exception as e:
            print(f"❌ 下载失败 {url}: {e}")
            continue
            
        # 分析内容
        fmt, behavior = analyze_content(content_str)
        print(f"🔍 识别结果 -> Format: {fmt}, Behavior: {behavior}")
        
        if behavior == "unknown":
            print(f"⚠️ 无法识别 {filename} 的 Behavior，已跳过。")
            continue
            
        # 转换并存储到 mrs_rules_sp
        convert_to_mrs(tmp_path, fmt, behavior, base_name)

if __name__ == "__main__":
    main()
