import requests
import os
from urllib.parse import urlparse

def postdata(data):
    json_data = {
        'name': 'hbgx',
        'displayName': 'github抓取',
        'form': '',
        'remark': '',
        'mergeSources': '',
        'ignoreFailedRemoteSub': 'quiet',
        'passThroughUA': False,
        'icon': 'https://raw.githubusercontent.com/cc63/ICON/main/icons/AMY.png',
        'isIconColor': True,
        'process': [
            {
                'type': 'Quick Setting Operator',
                'args': {
                    'useless': 'DISABLED',
                    'udp': 'DEFAULT',
                    'scert': 'DEFAULT',
                    'tfo': 'DEFAULT',
                    'vmess aead': 'DEFAULT',
                },
            },
            {
                'type': 'Type Filter',
                'args': {
                    'keep': False,
                    'value': [
                        'http',
                    ],
                },
                'customName': '',
                'id': '95060789.72173387',
                'disabled': False,
            },
            {
                'type': 'Script Operator',
                'args': {
                    'content': 'https://raw.githubusercontent.com/xujw3/other/refs/heads/main/rename.js#clear&flag',
                    'mode': 'link',
                    'arguments': {
                        'clear': True,
                        'flag': True,
                    },
                },
                'id': '36934923.422785416',
                'disabled': False,
            },
            {
                'type': 'Handle Duplicate Operator',
                'args': {
                    'action': 'delete',
                    'position': 'back',
                    'template': '0 1 2 3 4 5 6 7 8 9',
                    'link': '-',
                },
                'customName': '',
                'id': '40664239.26595869',
                'disabled': False,
            },
        ],
        'subUserinfo': 'upload=1000000000000; download=1000000000000; total=100000000000000; expire=4115721600; reset_day=1; plan_name=VIP9; app_url=https://sub.xujw.dpdns.org/',
        'proxy': '',
        'tag': [
            '第三方',
        ],
        'subscriptionTags': [],
        'source': 'remote',
        'url': data,
        'content': '',
        'ua': 'Clash Verge/1.7.1',
        'subscriptions': [],
        'display-name': 'github抓取',
    }
    # 1. 从环境变量获取 APIURL 字符串（建议用逗号分隔，例如：url1,url2,url3）
    api_env = os.getenv("APIURL", "")
    
    # 2. 将字符串拆分为列表，并去除多余空格
    # 如果 APIURL 为空，则返回空列表
    api_urls = [url.strip() for url in api_env.split(",") if url.strip()]
    
    if not api_urls:
        print("未找到有效的 APIURL，请检查环境变量设置。")
    else:
        for apiurl in api_urls:
            domain = urlparse(apiurl).netloc
            masked_url = f"{urlparse(apiurl).scheme}://{domain}/****/api/sub"
            try:
                # 执行 PATCH 请求
                response = requests.patch(
                    f'{apiurl.rstrip("/")}/hbgx', # 确保 URL 末尾没有多余的斜杠
                    json=json_data,
                    timeout=10 # 建议增加超时设置，防止脚本卡死
                )
                
                # 检查请求结果
                if response.status_code == 200:
                    print(f"✅ 成功更新: {masked_url}, 响应: {response.text}")
                else:
                    print(f"❌ 请求失败 ({masked_url}), 状态码: {response.status_code}, 响应: {response.text}")
                    
            except Exception as e:
                print(f"⚠️ 请求 {masked_url} 时发生异常: {e}")
    
    print("所有 API 处理完成。")
    return

def getdata(file_path):
    sub_list = []
    in_sub_list = False
    
    # 针对不同文件类型的处理
    file_name = os.path.basename(file_path)
    
    # 对于config_clash.txt、config_v2.txt和config-loon.txt使用相同的处理逻辑
    if file_name in ["config_clash.txt", "config_v2.txt", "config_loon.txt"]:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:  # 只要不是空行就添加
                    sub_list.append(stripped_line)
    else:
        # 原有的处理逻辑（针对其他文件，如config_sub_store.txt）
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line == '-- sub_list --':
                    in_sub_list = True
                elif stripped_line.startswith('--') and in_sub_list:
                    break  # 遇到下一个段落，停止提取
                elif in_sub_list and stripped_line:
                    sub_list.append(stripped_line)
    
    return sub_list  # 返回列表而不是字符串，便于后续合并

if __name__ == "__main__":
    # 更新需要处理的文件列表，增加了config_v2.txt和config-loon.txt
    paths = ["./config_sub_store.txt", "./config_clash.txt", "./config_v2.txt", "./config_loon.txt"]
    combined_results = []
    
    # 收集所有结果
    for path in paths:
        if os.path.exists(path):  # 确保文件存在
            result = getdata(path)
            combined_results.extend(result)  # 使用extend合并列表
        else:
            print(f"警告: 文件 {path} 不存在，已跳过。")
    
    # 将合并后的结果转换为字符串
    final_result = '\n'.join(combined_results)
    postdata(final_result)
