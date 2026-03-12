import asyncio
import aiohttp
import re
import yaml
import os
import base64
from urllib.parse import quote
from urllib.parse import urlparse
from tqdm import tqdm
from loguru import logger

# 全局配置
RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]"
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false&config=config%2FACL4SSR.ini"
CHECK_URL_LIST = ['api.dler.io', 'sub.xeton.dev', 'sub.id9.cc', 'sub.maoxiongnet.com']

# -------------------------------
# 订阅协议识别相关常量
# -------------------------------
PROTOCOL_SCHEMES = [
    "ss://", "ssr://", "vmess://", "trojan://", "vless://",
    "hysteria://", "hysteria2://", "hy2://", "tuic://",
    "shadowtls://", "shadow-tls://"
]
SCHEME_CANONICAL = {
    "hy2": "hysteria2",
    "shadow-tls": "shadowtls",
}
PROTOCOL_TYPES = [
    "ss", "ssr", "shadowsocks", "shadowsocksr",
    "vmess", "vless", "trojan",
    "hysteria", "hysteria2", "hy2", "tuic",
    "shadowtls", "shadow-tls",
    "reality"
]
TYPE_CANONICAL = {
    "shadowsocks": "ss",
    "shadowsocksr": "ssr",
    "hy2": "hysteria2",
    "shadow-tls": "shadowtls",
}
SCHEME_PATTERN = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(s) for s in PROTOCOL_SCHEMES) + r")",
    re.IGNORECASE
)
TYPE_PATTERN = re.compile(
    r"(?:type|protocol|security)\s*[:=]\s*[\"\']?"
    + r"(" + "|".join(PROTOCOL_TYPES) + r")"
    + r"[\"\']?",
    re.IGNORECASE
)
BASE64_TEXT_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")
CONFIG_HINTS = [
    "outbounds", "inbounds", "server", "port", "uuid", "password", "method",
    "cipher", "alterid", "tls", "sni", "alpn", "flow", "reality",
    "public_key", "short_id", "fingerprint", "transport", "network",
    "security", "obfs", "grpc", "ws", "path", "host"
]
CONFIG_HINT_THRESHOLD = 4

# -------------------------------
# 配置文件操作
# -------------------------------
def load_yaml_config(path_yaml):
    """读取 YAML 配置文件，如文件不存在则返回默认结构"""
    if os.path.exists(path_yaml):
        with open(path_yaml, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "机场订阅": [],
            "clash订阅": [],
            "v2订阅": [],
            "开心玩耍": [],
            "tgchannel": []
        }
    return config

def save_yaml_config(config, path_yaml):
    """保存配置到 YAML 文件"""
    with open(path_yaml, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True)

def get_config_channels(config_file='config.yaml'):
    """
    从配置文件中获取 Telegram 频道链接，
    将类似 https://t.me/univstar 转换为 https://t.me/s/univstar 格式
    """
    config = load_yaml_config(config_file)
    tgchannels = config.get('tgchannel', [])
    new_list = []
    for url in tgchannels:
        parts = url.strip().split('/')
        if parts:
            channel_id = parts[-1]
            new_list.append(f'https://t.me/s/{channel_id}')
    return new_list

# -------------------------------
# 异步 HTTP 请求辅助函数
# -------------------------------
async def fetch_content(url, session, method='GET', headers=None, timeout=15):
    """获取指定 URL 的文本内容"""
    try:
        async with session.request(method, url, headers=headers, timeout=timeout) as response:
            if response.status == 200:
                text = await response.text()
                return text
            else:
                logger.warning(f"URL {url} 返回状态 {response.status}")
                return None
    except Exception as e:
        logger.error(f"请求 {url} 异常: {e}")
        return None

# -------------------------------
# 频道抓取及订阅检查
# -------------------------------
async def get_channel_urls(channel_url, session):
    """从 Telegram 频道页面抓取所有订阅链接，并过滤无关链接"""
    content = await fetch_content(channel_url, session)
    if content:
        # 提取所有 URL，并排除包含“//t.me/”或“cdn-telegram.org”的链接
        all_urls = re.findall(RE_URL, content)
        filtered = [u for u in all_urls if "//t.me/" not in u and "cdn-telegram.org" not in u]
        logger.info(f"从 {channel_url} 提取 {len(filtered)} 个链接")
        return filtered
    else:
        logger.warning(f"无法获取 {channel_url} 的内容")
        return []

def normalize_protocol_name(value, mapping):
    """标准化协议名称（大小写/别名处理）"""
    if not value:
        return value
    value = value.lower()
    return mapping.get(value, value)

def detect_protocols(text):
    """从文本中提取协议类型，并估算节点数量"""
    if not text:
        return [], 0
    scheme_matches = SCHEME_PATTERN.findall(text)
    scheme_protocols = [
        normalize_protocol_name(match.lower().replace("://", ""), SCHEME_CANONICAL)
        for match in scheme_matches
    ]
    type_matches = TYPE_PATTERN.findall(text)
    type_protocols = [
        normalize_protocol_name(match.lower(), TYPE_CANONICAL)
        for match in type_matches
    ]
    protocols = scheme_protocols + type_protocols
    unique_protocols = sorted(set(protocols))
    count = max(len(scheme_matches), len(type_matches))
    if unique_protocols and count == 0:
        count = len(protocols)
    return unique_protocols, count

def count_config_hints(text):
    text_lower = text.lower()
    return sum(1 for hint in CONFIG_HINTS if hint in text_lower)

def looks_like_config(text):
    """判断文本是否像配置文件（JSON/YAML 等）"""
    if not text:
        return False
    if len(text.strip()) < 80:
        return False
    return count_config_hints(text) >= CONFIG_HINT_THRESHOLD

def try_decode_base64(text):
    """尝试对订阅内容进行 base64 解码（兼容 URL-safe & 缺失 padding）"""
    if not text:
        return None
    text_clean = text.strip().replace('\n', '').replace('\r', '')
    if len(text_clean) <= 20:
        return None
    if not BASE64_TEXT_RE.fullmatch(text_clean):
        return None
    pad_len = (-len(text_clean)) % 4
    if pad_len:
        text_clean += "=" * pad_len
    try:
        decoded = base64.urlsafe_b64decode(text_clean.encode('utf-8')).decode('utf-8', errors='ignore')
        if decoded and len(decoded.strip()) > 10:
            return decoded
    except Exception:
        return None
    return None

async def sub_check(url, session):
    """
    改进的订阅检查函数：
      - 判断响应头中的 subscription-userinfo 用于机场订阅
      - 判断内容中是否包含 'proxies:' 判定 clash 订阅
      - 识别更多协议（hysteria2/tuic/shadowtls/reality 等）
      - base64 解码与配置特征判断
      - 增加重试机制和更好的错误处理
    返回一个字典：{"url": ..., "type": ..., "info": ...}
    """
    headers = {
        'User-Agent': 'ClashforWindows/0.18.1',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate'
    }
    
    # 重试机制
    for attempt in range(2):
        try:
            async with session.get(url, headers=headers, timeout=12) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # 检查内容是否为空或过短
                    if not text or len(text.strip()) < 10:
                        logger.debug(f"订阅 {url} 内容为空或过短")
                        return None
                    
                    result = {"url": url, "type": None, "info": None}
                    
                    # 判断机场订阅（检查流量信息）
                    sub_info = response.headers.get('subscription-userinfo')
                    if sub_info:
                        nums = re.findall(r'\d+', sub_info)
                        if len(nums) >= 3:
                            upload, download, total = map(int, nums[:3])
                            if total > 0:  # 确保总流量大于0
                                unused = (total - upload - download) / (1024 ** 3)
                                if unused > 0:
                                    result["type"] = "机场订阅"
                                    result["info"] = f"可用流量: {round(unused, 2)} GB"
                                    return result
                    
                    # 判断 clash 订阅 - 更严格的检查
                    if "proxies:" in text and ("name:" in text or "server:" in text):
                        proxy_count = text.count("- name:")
                        if proxy_count > 0:
                            result["type"] = "clash订阅"
                            result["info"] = f"包含 {proxy_count} 个节点"
                            return result
                    
                    decoded = None
                    try:
                        decoded = try_decode_base64(text)
                    except Exception as e:
                        logger.debug(f"订阅 {url} base64检测异常: {e}")

                    # 优先识别原始格式协议链接
                    protocols, node_count = detect_protocols(text)
                    if protocols:
                        result["type"] = "v2订阅"
                        if node_count > 0:
                            result["info"] = f"包含 {node_count} 个节点 ({'/'.join(protocols)})"
                        else:
                            result["info"] = f"识别协议: {'/'.join(protocols)}"
                        logger.debug(f"订阅 {url} 识别为原始格式订阅: {protocols}")
                        return result

                    # base64 解码内容的协议识别
                    if decoded:
                        decoded_protocols, decoded_count = detect_protocols(decoded)
                        if decoded_protocols:
                            result["type"] = "v2订阅"
                            count_info = decoded_count if decoded_count > 0 else "多"
                            result["info"] = f"包含 {count_info} 个节点 (base64: {'/'.join(decoded_protocols)})"
                            logger.debug(
                                f"订阅 {url} 识别为 base64 协议订阅: {decoded_protocols}"
                            )
                            return result

                        # 解码后如果是配置文件
                        if looks_like_config(decoded):
                            lines = [line.strip() for line in decoded.split('\n') if line.strip()]
                            result["type"] = "v2订阅"
                            result["info"] = f"包含 {len(lines)} 行配置 (base64)"
                            logger.debug(f"订阅 {url} 识别为 base64 配置文件")
                            return result

                    # 原文是 JSON/YAML 配置的情况
                    if looks_like_config(text):
                        protocols_from_config, config_count = detect_protocols(text)
                        result["type"] = "v2订阅"
                        if protocols_from_config:
                            count_info = config_count if config_count > 0 else "多"
                            result["info"] = (
                                f"包含 {count_info} 个节点 (配置: {'/'.join(protocols_from_config)})"
                            )
                        else:
                            result["info"] = "疑似配置订阅"
                        logger.debug(f"订阅 {url} 识别为配置订阅")
                        return result
                    
                    
                    # 如果内容看起来像配置但不匹配已知格式，记录调试信息
                    if len(text) > 100:
                        # 显示内容的前100个字符用于调试
                        preview = text[:100].replace('\n', '\\n').replace('\r', '\\r')
                        logger.info(f"⚠️  订阅 {url} 内容不匹配已知格式")
                        logger.info(f"   长度: {len(text)} 字符")
                        logger.info(f"   预览: {preview}...")
                        
                        # 检查是否可能是其他格式
                        if 'http' in text.lower() or 'server' in text.lower():
                            logger.info(f"   可能包含服务器配置，但格式未识别")
                    
                    return None
                    
                elif response.status in [403, 404, 410, 500]:
                    # 这些状态码通常表示永久失败
                    logger.debug(f"订阅检查 {url} 返回状态 {response.status}")
                    return None
                else:
                    logger.warning(f"订阅检查 {url} 返回状态 {response.status}")
                    if attempt == 0:  # 第一次失败，重试
                        await asyncio.sleep(1)
                        continue
                    return None
                    
        except asyncio.TimeoutError:
            logger.debug(f"订阅检查 {url} 超时，尝试 {attempt + 1}/2")
            if attempt == 0:
                await asyncio.sleep(1)
                continue
        except Exception as e:
            logger.debug(f"订阅检查 {url} 异常: {e}，尝试 {attempt + 1}/2")
            if attempt == 0:
                await asyncio.sleep(1)
                continue
    
    return None

# -------------------------------
# 节点有效性检测（根据多个检测入口）
# -------------------------------
async def url_check_valid(url, target, session):
    """
    改进的节点有效性检测：
    通过遍历多个检测入口检查订阅节点有效性，
    不仅检查状态码，还验证返回内容的有效性。
    """
    encoded_url = quote(url, safe='')
    
    for check_base in CHECK_URL_LIST:
        check_url = CHECK_NODE_URL_STR.format(check_base, target, encoded_url)
        try:
            async with session.get(check_url, timeout=20) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 检查返回内容是否有效
                    if not content or len(content.strip()) < 50:
                        logger.debug(f"节点检测 {url} 在 {check_base} 返回内容过短")
                        continue
                    
                    # 根据目标类型验证内容
                    if target == "clash":
                        if "proxies:" in content and ("name:" in content or "server:" in content):
                            proxy_count = content.count("- name:")
                            if proxy_count > 0:
                                logger.debug(f"节点检测 {url} 在 {check_base} 成功，包含 {proxy_count} 个节点")
                                return url
                    elif target == "loon":
                        # Loon格式通常包含[Proxy]段落
                        if "[Proxy]" in content or "=" in content:
                            logger.debug(f"节点检测 {url} 在 {check_base} 成功 (Loon格式)")
                            return url
                    elif target == "v2ray":
                        # V2Ray格式可能是JSON或其他格式
                        if len(content.strip()) > 100:  # 基本长度检查
                            logger.debug(f"节点检测 {url} 在 {check_base} 成功 (V2Ray格式)")
                            return url
                    else:
                        # 其他格式，基本长度检查
                        if len(content.strip()) > 100:
                            logger.debug(f"节点检测 {url} 在 {check_base} 成功")
                            return url
                    
                    logger.debug(f"节点检测 {url} 在 {check_base} 内容格式不匹配")
                else:
                    logger.debug(f"节点检测 {url} 在 {check_base} 返回状态 {resp.status}")
                    
        except asyncio.TimeoutError:
            logger.debug(f"节点检测 {url} 在 {check_base} 超时")
            continue
        except Exception as e:
            logger.debug(f"节点检测 {url} 在 {check_base} 异常: {e}")
            continue
    
    logger.debug(f"节点检测 {url} 在所有检测点都失败")
    return None

# -------------------------------
# 主流程：更新订阅与合并
# -------------------------------
async def update_today_sub(session):
    """
    从 Telegram 频道获取最新订阅链接，
    返回一个去重后的 URL 列表
    """
    tg_channels = get_config_channels('config.yaml')
    all_urls = []
    for channel in tg_channels:
        urls = await get_channel_urls(channel, session)
        all_urls.extend(urls)
    return list(set(all_urls))

async def check_subscriptions(urls):
    """
    异步检查所有订阅链接的有效性，
    返回检查结果列表，每个结果为字典 {url, type, info}
    """
    if not urls:
        return []
    
    results = []
    # 创建连接器，限制并发连接数
    connector = aiohttp.TCPConnector(
        limit=100,
        limit_per_host=20,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )
    
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # 使用信号量限制并发数
        semaphore = asyncio.Semaphore(50)
        
        async def check_single(url):
            async with semaphore:
                return await sub_check(url, session)
        
        tasks = [check_single(url) for url in urls]
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="订阅筛选"):
            res = await coro
            if res:
                results.append(res)
    return results

async def check_nodes(urls, target, session):
    """
    异步检查每个订阅节点的有效性，
    返回检测有效的节点 URL 列表
    """
    if not urls:
        return []
    
    valid_urls = []
    # 使用信号量限制并发数
    semaphore = asyncio.Semaphore(20)  # 节点检测并发数较低，避免被封
    
    async def check_single_node(url):
        async with semaphore:
            return await url_check_valid(url, target, session)
    
    tasks = [check_single_node(url) for url in urls]
    for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"检测{target}节点"):
        res = await coro
        if res:
            valid_urls.append(res)
    return valid_urls

def write_url_list(url_list, file_path):
    """将 URL 列表写入文本文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(url_list))
    logger.info(f"已保存 {len(url_list)} 个链接到 {file_path}")
from urllib.parse import urlparse

# -------------------------------
# 链接去重辅助函数 (复用)
# -------------------------------
def get_domain(url):
    """提取 URL 的主域名（hostname）"""
    try:
        # urlparse解析URL，获取网络位置（netloc），即域名+端口
        netloc = urlparse(url).netloc
        if not netloc:
            # 如果netloc为空，可能不是一个完整的URL，尝试直接返回
            return url
        # 移除可能的端口号（如:8080）
        domain = netloc.split(':')[0]
        # 移除 www. 前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception as e:
        logger.warning(f"无法解析 URL: {url}，异常: {e}")
        return url

def deduplicate_urls_by_domain(url_list):
    """
    根据主域名对 URL 列表进行去重。
    保留列表中每个主域名下的 '最后一个' 链接。
    """
    domain_to_url = {}
    
    for url in url_list:
        # 对于 "开心玩耍" 列表，链接在字符串的末尾，需要先提取URL
        cleaned_url = url.split(' ')[-1] if ' ' in url and 'http' in url else url
        
        domain = get_domain(cleaned_url)
        if domain:
            # 存储的是完整的原始字符串，以便保留 "可用流量: XX GB" 信息
            domain_to_url[domain] = url 
        else:
            domain_to_url[url] = url
            
    deduped_urls = list(domain_to_url.values())
    logger.info(f"去重前链接数: {len(url_list)}, 去重后链接数: {len(deduped_urls)}")
    
    return deduped_urls
# -------------------------------
# 主函数入口
# -------------------------------
async def validate_existing_subscriptions(config, session):
    """验证现有订阅的有效性，移除失效订阅"""
    logger.info("🔍 开始验证现有订阅的有效性...")
    
    all_existing_urls = []
    
    # 提取所有现有订阅URL
    for category in ["机场订阅", "clash订阅", "v2订阅"]:
        for item in config.get(category, []):
            if isinstance(item, str) and item.strip():
                all_existing_urls.append((item.strip(), category))
    
    # 从开心玩耍中提取URL
    for item in config.get("开心玩耍", []):
        if isinstance(item, str) and item.strip():
            url_match = re.search(r'https?://[^\s]+', item)
            if url_match:
                all_existing_urls.append((url_match.group(), "开心玩耍"))
    
    if not all_existing_urls:
        logger.info("📝 没有现有订阅需要验证")
        return {"机场订阅": [], "clash订阅": [], "v2订阅": [], "开心玩耍": []}
    
    logger.info(f"📊 需要验证 {len(all_existing_urls)} 个现有订阅")
    
    # 使用信号量限制并发
    semaphore = asyncio.Semaphore(30)
    
    async def check_single_existing(url_info):
        url, category = url_info
        async with semaphore:
            result = await sub_check(url, session)
            return (url, category, result)
    
    valid_existing = {"机场订阅": [], "clash订阅": [], "v2订阅": [], "开心玩耍": []}
    tasks = [check_single_existing(url_info) for url_info in all_existing_urls]
    
    for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="验证现有订阅"):
        url, category, result = await coro
        if result:
            if result["type"] == "机场订阅":
                valid_existing["机场订阅"].append(url)
                if result["info"]:
                    valid_existing["开心玩耍"].append(f'{result["info"]} {url}')
            elif result["type"] == "clash订阅":
                valid_existing["clash订阅"].append(url)
            elif result["type"] == "v2订阅":
                valid_existing["v2订阅"].append(url)
    
    # 统计验证结果
    total_original = len(all_existing_urls)
    total_valid = sum(len(valid_existing[cat]) for cat in ["机场订阅", "clash订阅", "v2订阅"])
    
    logger.info(f"✅ 现有订阅验证完成: {total_original} → {total_valid} (有效率: {total_valid/total_original*100:.1f}%)")
    
    return valid_existing

async def main():
    config_path = 'config.yaml'
    
    logger.info("🚀 开始订阅管理流程...")
    logger.info("=" * 60)
    
    # 加载现有配置
    config = load_yaml_config(config_path)
    
    # 统计原始数据
    original_counts = {}
    for category in ["机场订阅", "clash订阅", "v2订阅", "开心玩耍"]:
        original_counts[category] = len(config.get(category, []))
    
    logger.info("📊 原始配置统计:")
    for category, count in original_counts.items():
        logger.info(f"   {category}: {count:,} 个")
    
    # 创建优化的会话
    connector = aiohttp.TCPConnector(
        limit=100,
        limit_per_host=20,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        
        # 第一步：验证现有订阅
        logger.info("\n🔍 第一步：验证现有订阅")
        logger.info("-" * 40)
        valid_existing = await validate_existing_subscriptions(config, session)
        
        # 第二步：获取新的订阅链接
        logger.info("\n📡 第二步：获取新的订阅链接")
        logger.info("-" * 40)
        today_urls = await update_today_sub(session)
        logger.info(f"📥 从 Telegram 频道获得 {len(today_urls)} 个新链接")
        
        # 第三步：检查新订阅的有效性
        logger.info("\n🔍 第三步：检查新订阅有效性")
        logger.info("-" * 40)
        new_results = await check_subscriptions(today_urls)
        
        # 分类新订阅
        new_subs = [res["url"] for res in new_results if res and res["type"] == "机场订阅"]
        new_clash = [res["url"] for res in new_results if res and res["type"] == "clash订阅"]
        new_v2 = [res["url"] for res in new_results if res and res["type"] == "v2订阅"]
        new_play = [f'{res["info"]} {res["url"]}' for res in new_results 
                   if res and res["type"] == "机场订阅" and res["info"]]
        
        logger.info(f"✅ 新增有效订阅: 机场{len(new_subs)}个, clash{len(new_clash)}个, v2{len(new_v2)}个")
        
        # 第四步：合并有效订阅
        logger.info("\n🔄 第四步：合并有效订阅")
        logger.info("-" * 40)
        
        # 1. 初步合并和去重 (set() 自动去重)
        merged_subs = sorted(list(set(valid_existing["机场订阅"] + new_subs)))
        merged_clash = sorted(list(set(valid_existing["clash订阅"] + new_clash)))
        merged_v2 = sorted(list(set(valid_existing["v2订阅"] + new_v2)))
        merged_play = sorted(list(set(valid_existing["开心玩耍"] + new_play)))
        
        # 2. **新增：主域名去重**
        logger.info("开始对 '机场订阅' 列表进行主域名去重...")
        final_subs_deduped = deduplicate_urls_by_domain(merged_subs)
        
        # '开心玩耍' 包含流量信息，也需要去重
        logger.info("开始对 '开心玩耍' 列表进行主域名去重...")
        final_play_deduped = deduplicate_urls_by_domain(merged_play)
        
        # clash 和 v2 在这里不需要去重，因为它们会在第六步生成输出文件时再次去重
        # 但为了保证 config.yaml 本身是干净的，也进行去重
        logger.info("开始对 'clash订阅' 列表进行主域名去重...")
        final_clash_deduped = deduplicate_urls_by_domain(merged_clash)
        
        logger.info("开始对 'v2订阅' 列表进行主域名去重...")
        final_v2_deduped = deduplicate_urls_by_domain(merged_v2)
        
        final_config = {
            "机场订阅": final_subs_deduped,
            "clash订阅": final_clash_deduped,
            "v2订阅": final_v2_deduped,
            "开心玩耍": final_play_deduped,
            "tgchannel": config.get("tgchannel", [])  # 保留频道配置
        }
        
        # 统计最终结果
        logger.info("📈 最终统计对比:")
        total_original = sum(original_counts.values())
        total_final = sum(len(final_config[cat]) for cat in ["机场订阅", "clash订阅", "v2订阅", "开心玩耍"])
        
        for category in ["机场订阅", "clash订阅", "v2订阅", "开心玩耍"]:
            original = original_counts[category]
            final = len(final_config[category])
            change = final - original
            change_str = f"(+{change})" if change > 0 else f"({change})" if change < 0 else "(=)"
            logger.info(f"   {category}: {original:,} → {final:,} {change_str}")
        
        logger.info(f"📊 总体: {total_original:,} → {total_final:,} "
                   f"(清理率: {(total_original-total_final)/total_original*100:.1f}%)")
        
        # 保存更新后的配置
        save_yaml_config(final_config, config_path)
        logger.info("💾 配置文件已更新")
        
        # 第五步：生成输出文件
        logger.info("\n📝 第五步：生成输出文件")
        logger.info("-" * 40)
        
        # 写入订阅存储文件
        sub_store_file = config_path.replace('.yaml', '_sub_store.txt')
        content = ("-- play_list --\n\n" + 
                  "\n".join(final_config["开心玩耍"]) + 
                  "\n\n-- sub_list --\n\n" + 
                  "\n".join(final_config["机场订阅"]))
        with open(sub_store_file, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"📄 订阅存储文件已保存: {sub_store_file}")
        
        # 第六步：检测节点有效性
        logger.info("\n🔍 第六步：检测节点有效性")
        logger.info("-" * 40)
        
        # 检测机场订阅节点
        if final_config["机场订阅"]:
            valid_loon = await check_nodes(final_config["机场订阅"], "loon", session)
            
            # --- 新增去重逻辑 ---
            if valid_loon:
                logger.info("开始对 loon 订阅链接进行主域名去重...")
                valid_loon = deduplicate_urls_by_domain(valid_loon)
            # --------------------
            
            loon_file = config_path.replace('.yaml', '_loon.txt')
            write_url_list(valid_loon, loon_file)
        
        # 检测clash订阅节点
        if final_config["clash订阅"]:
            valid_clash = await check_nodes(final_config["clash订阅"], "clash", session)
            
            # --- 新增去重逻辑 ---
            if valid_clash:
                logger.info("开始对 clash 订阅链接进行主域名去重...")
                valid_clash = deduplicate_urls_by_domain(valid_clash)
            # --------------------
            
            clash_file = config_path.replace('.yaml', '_clash.txt')
            write_url_list(valid_clash, clash_file)
        
        # 检测v2订阅节点
        if final_config["v2订阅"]:
            valid_v2 = await check_nodes(final_config["v2订阅"], "v2ray", session)
            
            # --- 新增去重逻辑 ---
            if valid_v2:
                logger.info("开始对 v2 订阅链接进行主域名去重...")
                valid_v2 = deduplicate_urls_by_domain(valid_v2)
            # --------------------
            
            v2_file = config_path.replace('.yaml', '_v2.txt')
            write_url_list(valid_v2, v2_file)
    
    logger.info("\n🎉 订阅管理流程完成！")
    logger.info("=" * 60)

if __name__ == '__main__':
    asyncio.run(main())
