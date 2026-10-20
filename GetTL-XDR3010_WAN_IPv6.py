import requests
import hashlib
import ipaddress
import sys
import time
#此脚本仅在TL-XDR3010路由器、固件版本1.0.23测试使用。

#This script has been tested exclusively on the TL-XDR3010 router with firmware version 1.0.23.


# ============ 配置区 ============
ROUTER_URL = "http://192.168.0.1"  #输入你路由器的地址
PLAIN_PASSWORD = "PASSWORD"
# ================================

CHARSET = (
    '01234567890123456789012345678901'
    ' !"#$%&\'()*+,-./'
    '0123456789:;<=>?@'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '[\\]^_`'
    'abcdefghijklmnopqrstuvwxyz'
    '{|}~'
)

PAYLOADS_TO_TRY = [
    {"network": {"name": ["wanv6_status"]}, "method": "get"},
    {"network": {"name": "wanv6_status"}, "method": "get"},
    {"network": {"name": ["wan_status", "wanv6_status"]}, "method": "get"},
    {"network": {"name": ["wan_status", "wan_status_2", "wanv6_status", "wanv6_status_2"]}, "method": "get"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Content-Type": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": ROUTER_URL,
    "Referer": ROUTER_URL + "/",
}


def variant_md5(s):
    """路由器 md5.js：每个字符取 CHARSET 中最后一次出现的位置，再做标准 MD5"""
    data = bytearray()
    for ch in s:
        idx = CHARSET.rfind(ch)
        if idx < 0:
            idx = 0
        data.append(idx & 0xFF)
    return hashlib.md5(bytes(data)).hexdigest()


def is_valid_public_ipv6(addr_str):
    if not addr_str:
        return False
    try:
        addr = ipaddress.IPv6Address(addr_str)
    except ValueError:
        return False
    return not (
        addr.is_unspecified
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_private
    )


def extract_ipv6(network):
    if not isinstance(network, dict):
        return None
    wanv6 = network.get("wanv6_status")
    if not isinstance(wanv6, dict):
        return None
    return wanv6.get("ip6addr")


def get_nonce(session):
    """使用浏览器实际使用的载荷获取 nonce"""
    for attempt in range(3):
        try:
            # 先 GET 首页建立会话
            session.get(ROUTER_URL, headers=HEADERS, timeout=10)
            # 关键：载荷改为浏览器实际使用的 get_encrypt_info
            resp = session.post(
                ROUTER_URL,
                json={"method": "do", "user_management": {"get_encrypt_info": None}},
                headers=HEADERS,
                timeout=10,
            )
            data = resp.json()
            if data.get("nonce"):
                return data["nonce"]
            print(f"  第{attempt+1}次获取 nonce 失败: {data}", file=sys.stderr)
        except Exception as e:
            print(f"  第{attempt+1}次异常: {e}", file=sys.stderr)
        time.sleep(2)
    return None


def main():
    session = requests.Session()

    # 1. 自动获取 nonce
    nonce = get_nonce(session)
    if not nonce:
        print("自动获取 nonce 失败", file=sys.stderr)
        return 1

    print(f"nonce: {nonce}", file=sys.stderr)

    # 2. 计算密码并登录
    password = variant_md5(PLAIN_PASSWORD + ":" + nonce)
    print(f"password: {password}", file=sys.stderr)

    login_payload = {
        "method": "do",
        "login": {"password": password, "encrypt_type": "3"},
    }

    try:
        resp = session.post(ROUTER_URL, json=login_payload, headers=HEADERS, timeout=10)
        data = resp.json()
    except Exception as e:
        print(f"登录请求异常: {e}", file=sys.stderr)
        return 1

    if data.get("error_code") != 0 or not data.get("stok"):
        print(f"登录失败: {data}", file=sys.stderr)
        return 1

    print("登录成功", file=sys.stderr)
    stok = data["stok"]
    api_url = f"{ROUTER_URL}/stok={stok}/ds"

    # 3. 提取 WAN IPv6
    last_error = "所有载荷尝试均失败"
    for payload in PAYLOADS_TO_TRY:
        try:
            wan_resp = session.post(api_url, json=payload, headers=HEADERS, timeout=10)
            wan_data = wan_resp.json()
        except Exception as e:
            last_error = f"请求异常: {e}"
            continue

        ipv6_addr = extract_ipv6(wan_data.get("network"))
        if is_valid_public_ipv6(ipv6_addr):
            print(ipv6_addr)
            return 0

        if ipv6_addr:
            last_error = f"获取到地址但无效: {ipv6_addr}"
        else:
            last_error = f"载荷未返回 wanv6_status.ip6addr，响应摘要: {str(wan_data)[:200]}"

    print(last_error, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())