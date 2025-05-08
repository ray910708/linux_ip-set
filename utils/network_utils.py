#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 網絡工具函數
提供各種網絡相關的實用函數

功能:
1. IP地址和子網掩碼轉換
2. CIDR表示法處理
3. IP地址範圍計算
4. 基本網絡地址驗證
"""

import ipaddress
import socket
import re
from typing import Tuple, List, Optional, Union, Generator

def validate_ip(ip: str) -> bool:
    """
    驗證IPv4地址格式
    
    參數:
        ip (str): 要驗證的IP地址
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def validate_ip_cidr(ip_cidr: str) -> bool:
    """
    驗證CIDR格式的IPv4地址
    
    參數:
        ip_cidr (str): 要驗證的CIDR格式IP地址 (如 192.168.1.1/24)
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    try:
        ipaddress.IPv4Network(ip_cidr, strict=False)
        return True
    except ValueError:
        return False

def validate_netmask(netmask: str) -> bool:
    """
    驗證IPv4子網掩碼格式
    
    參數:
        netmask (str): 要驗證的子網掩碼 (如 255.255.255.0)
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    # 常見的子網掩碼列表
    valid_netmasks = {
        '255.0.0.0',        # /8
        '255.128.0.0',      # /9
        '255.192.0.0',      # /10
        '255.224.0.0',      # /11
        '255.240.0.0',      # /12
        '255.248.0.0',      # /13
        '255.252.0.0',      # /14
        '255.254.0.0',      # /15
        '255.255.0.0',      # /16
        '255.255.128.0',    # /17
        '255.255.192.0',    # /18
        '255.255.224.0',    # /19
        '255.255.240.0',    # /20
        '255.255.248.0',    # /21
        '255.255.252.0',    # /22
        '255.255.254.0',    # /23
        '255.255.255.0',    # /24
        '255.255.255.128',  # /25
        '255.255.255.192',  # /26
        '255.255.255.224',  # /27
        '255.255.255.240',  # /28
        '255.255.255.248',  # /29
        '255.255.255.252',  # /30
        '255.255.255.254',  # /31
        '255.255.255.255',  # /32
    }
    
    return netmask in valid_netmasks

def cidr_to_netmask(cidr: int) -> str:
    """
    將CIDR前綴長度轉換為子網掩碼
    
    參數:
        cidr (int): CIDR前綴長度 (1-32)
        
    返回:
        str: 子網掩碼
        
    異常:
        ValueError: 如果CIDR前綴長度無效
    """
    if not isinstance(cidr, int) or cidr < 0 or cidr > 32:
        raise ValueError("CIDR前綴長度必須是0-32之間的整數")
    
    # 計算子網掩碼
    mask = (0xffffffff << (32 - cidr)) & 0xffffffff
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

def netmask_to_cidr(netmask: str) -> int:
    """
    將子網掩碼轉換為CIDR前綴長度
    
    參數:
        netmask (str): 子網掩碼 (如 255.255.255.0)
        
    返回:
        int: CIDR前綴長度
        
    異常:
        ValueError: 如果子網掩碼格式無效
    """
    if not validate_netmask(netmask):
        raise ValueError("無效的子網掩碼格式")
    
    # 計算二進制中1的個數
    parts = netmask.split('.')
    binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(
        int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
    )
    return binary.count('1')

def ip_to_int(ip: str) -> int:
    """
    將IP地址轉換為整數
    
    參數:
        ip (str): IP地址 (如 192.168.1.1)
        
    返回:
        int: IP地址的整數表示
        
    異常:
        ValueError: 如果IP地址格式無效
    """
    if not validate_ip(ip):
        raise ValueError("無效的IP地址格式")
    
    octets = ip.split('.')
    return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])

def int_to_ip(ip_int: int) -> str:
    """
    將整數轉換為IP地址
    
    參數:
        ip_int (int): IP地址的整數表示
        
    返回:
        str: IP地址
        
    異常:
        ValueError: 如果整數超出IP地址範圍
    """
    if not 0 <= ip_int <= 0xffffffff:
        raise ValueError("整數超出IP地址範圍")
    
    return f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"

def get_ip_range(network_cidr: str) -> Tuple[str, str]:
    """
    獲取CIDR格式網絡的IP範圍
    
    參數:
        network_cidr (str): CIDR格式的網絡地址 (如 192.168.1.0/24)
        
    返回:
        Tuple[str, str]: (起始IP, 結束IP)
        
    異常:
        ValueError: 如果網絡地址格式無效
    """
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        return (str(network.network_address), str(network.broadcast_address))
    except ValueError as e:
        raise ValueError(f"無效的網絡地址格式: {e}")

def get_network_info(ip_cidr: str) -> dict:
    """
    獲取CIDR格式網絡的詳細信息
    
    參數:
        ip_cidr (str): CIDR格式的IP地址 (如 192.168.1.1/24)
        
    返回:
        dict: 包含網絡信息的字典
        
    異常:
        ValueError: 如果IP地址格式無效
    """
    try:
        # 解析CIDR
        ip, prefix = ip_cidr.split('/')
        prefix = int(prefix)
        
        # 創建網絡對象
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        
        # 收集網絡信息
        info = {
            'ip': ip,
            'cidr': prefix,
            'netmask': cidr_to_netmask(prefix),
            'network': str(network.network_address),
            'broadcast': str(network.broadcast_address),
            'first_host': str(network.network_address + 1),
            'last_host': str(network.broadcast_address - 1),
            'num_hosts': network.num_addresses - 2,
            'total_addresses': network.num_addresses
        }
        
        return info
    except ValueError as e:
        raise ValueError(f"無效的CIDR格式IP地址: {e}")

def generate_ip_addresses(start_ip: str, count: int) -> Generator[str, None, None]:
    """
    生成連續的IP地址
    
    參數:
        start_ip (str): 起始IP地址
        count (int): 要生成的IP地址數量
        
    返回:
        Generator[str, None, None]: IP地址生成器
        
    異常:
        ValueError: 如果IP地址格式無效或數量為負數
    """
    if not validate_ip(start_ip):
        raise ValueError("無效的起始IP地址格式")
    if count < 0:
        raise ValueError("IP地址數量不能為負數")
    
    # 將起始IP轉換為整數
    ip_int = ip_to_int(start_ip)
    
    # 生成指定數量的IP地址
    for i in range(count):
        yield int_to_ip(ip_int + i)

def is_ip_in_network(ip: str, network_cidr: str) -> bool:
    """
    檢查IP地址是否在指定的網絡範圍內
    
    參數:
        ip (str): IP地址
        network_cidr (str): CIDR格式的網絡地址
        
    返回:
        bool: 如果IP在網絡範圍內返回True，否則返回False
        
    異常:
        ValueError: 如果IP地址或網絡地址格式無效
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        return ip_obj in network
    except ValueError as e:
        raise ValueError(f"無效的IP或網絡地址格式: {e}")

def get_valid_netmasks() -> List[Tuple[str, str]]:
    """
    獲取有效的子網掩碼列表，每個項目包含掩碼和CIDR表示
    
    返回:
        List[Tuple[str, str]]: 子網掩碼列表，格式為 [(掩碼, CIDR表示), ...]
    """
    netmasks = []
    for cidr in range(8, 33):
        mask = cidr_to_netmask(cidr)
        netmasks.append((mask, f"/{cidr}"))
    return netmasks

def validate_hostname(hostname: str) -> bool:
    """
    驗證主機名格式
    
    參數:
        hostname (str): 要驗證的主機名
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    # 先檢查是否為IP地址
    if validate_ip(hostname):
        return True
    
    # 主機名格式的正則表達式
    pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    return bool(re.match(pattern, hostname))

def validate_port(port: Union[str, int]) -> bool:
    """
    驗證端口號
    
    參數:
        port (Union[str, int]): 要驗證的端口號
        
    返回:
        bool: 如果端口號有效返回True，否則返回False
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def resolve_hostname(hostname: str) -> Optional[str]:
    """
    解析主機名為IP地址
    
    參數:
        hostname (str): 要解析的主機名
        
    返回:
        Optional[str]: 解析得到的IP地址，如果解析失敗則返回None
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def is_valid_mac(mac: str) -> bool:
    """
    驗證MAC地址格式
    
    參數:
        mac (str): 要驗證的MAC地址
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    # 支持多種MAC地址格式
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # 00:11:22:33:44:55 或 00-11-22-33-44-55
        r'^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$',   # 0011.2233.4455
    ]
    
    return any(re.match(pattern, mac) for pattern in patterns)

def format_mac(mac: str, separator: str = ':') -> str:
    """
    格式化MAC地址
    
    參數:
        mac (str): MAC地址
        separator (str, optional): 分隔符，默認為':'
        
    返回:
        str: 格式化後的MAC地址
        
    異常:
        ValueError: 如果MAC地址格式無效
    """
    if not is_valid_mac(mac):
        raise ValueError("無效的MAC地址格式")
    
    # 提取16進制數字
    hex_digits = ''.join([c for c in mac if c.isalnum()])
    
    # 格式化MAC地址
    formatted = []
    for i in range(0, len(hex_digits), 2):
        formatted.append(hex_digits[i:i+2])
    
    return separator.join(formatted)

def calculate_broadcast_address(ip: str, netmask: str) -> str:
    """
    計算廣播地址
    
    參數:
        ip (str): IP地址
        netmask (str): 子網掩碼
        
    返回:
        str: 廣播地址
        
    異常:
        ValueError: 如果IP地址或子網掩碼格式無效
    """
    if not validate_ip(ip) or not validate_netmask(netmask):
        raise ValueError("無效的IP地址或子網掩碼格式")
    
    # 將IP和掩碼轉換為整數
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(netmask)
    
    # 計算廣播地址
    broadcast_int = ip_int | (~mask_int & 0xffffffff)
    
    return int_to_ip(broadcast_int)

def calculate_network_address(ip: str, netmask: str) -> str:
    """
    計算網絡地址
    
    參數:
        ip (str): IP地址
        netmask (str): 子網掩碼
        
    返回:
        str: 網絡地址
        
    異常:
        ValueError: 如果IP地址或子網掩碼格式無效
    """
    if not validate_ip(ip) or not validate_netmask(netmask):
        raise ValueError("無效的IP地址或子網掩碼格式")
    
    # 將IP和掩碼轉換為整數
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(netmask)
    
    # 計算網絡地址
    network_int = ip_int & mask_int
    
    return int_to_ip(network_int)