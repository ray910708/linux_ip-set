#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 數據驗證工具
提供各種數據格式的驗證函數

功能:
1. 網絡參數驗證（IP地址、子網掩碼、端口等）
2. 文件路徑和權限驗證
3. 輸入數據格式檢查
4. 系統參數驗證
"""

import re
import os
import ipaddress
from typing import Union, Any, List, Dict, Tuple, Optional

def is_valid_ip(ip: str) -> bool:
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

def is_valid_ip_cidr(ip_cidr: str) -> bool:
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

def is_valid_netmask(netmask: str) -> bool:
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

def is_valid_hostname(hostname: str) -> bool:
    """
    驗證主機名格式
    
    參數:
        hostname (str): 要驗證的主機名
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    # 先檢查是否為IP地址
    if is_valid_ip(hostname):
        return True
    
    # 主機名格式的正則表達式
    pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    return bool(re.match(pattern, hostname))

def is_valid_port(port: Union[str, int]) -> bool:
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

def is_valid_file_path(path: str, check_exists: bool = True) -> bool:
    """
    驗證文件路徑格式
    
    參數:
        path (str): 要驗證的文件路徑
        check_exists (bool, optional): 是否檢查文件是否存在，默認為True
        
    返回:
        bool: 如果路徑有效返回True，否則返回False
    """
    # 基本路徑格式檢查
    if not path or len(path) > 260:  # Windows MAX_PATH限制
        return False
    
    # 如果需要檢查文件是否存在
    if check_exists:
        return os.path.isfile(path)
    
    return True

def is_valid_dir_path(path: str, check_exists: bool = True) -> bool:
    """
    驗證目錄路徑格式
    
    參數:
        path (str): 要驗證的目錄路徑
        check_exists (bool, optional): 是否檢查目錄是否存在，默認為True
        
    返回:
        bool: 如果路徑有效返回True，否則返回False
    """
    # 基本路徑格式檢查
    if not path or len(path) > 260:  # Windows MAX_PATH限制
        return False
    
    # 如果需要檢查目錄是否存在
    if check_exists:
        return os.path.isdir(path)
    
    return True

def is_valid_file_permission(path: str, mode: str) -> bool:
    """
    檢查文件權限
    
    參數:
        path (str): 文件路徑
        mode (str): 權限模式 ('r' for read, 'w' for write, 'x' for execute)
        
    返回:
        bool: 如果有指定權限返回True，否則返回False
    """
    if not os.path.exists(path):
        return False
    
    if mode == 'r':
        return os.access(path, os.R_OK)
    elif mode == 'w':
        return os.access(path, os.W_OK)
    elif mode == 'x':
        return os.access(path, os.X_OK)
    else:
        return False

def is_empty_string(value: str) -> bool:
    """
    檢查字符串是否為空
    
    參數:
        value (str): 要檢查的字符串
        
    返回:
        bool: 如果字符串為空或只包含空白字符返回True，否則返回False
    """
    return value is None or value.strip() == ""

def is_valid_number(value: str, min_val: Optional[float] = None, max_val: Optional[float] = None) -> bool:
    """
    驗證字符串是否為有效數字，並檢查範圍
    
    參數:
        value (str): 要驗證的字符串
        min_val (Optional[float]): 最小值限制，默認為None表示不限制
        max_val (Optional[float]): 最大值限制，默認為None表示不限制
        
    返回:
        bool: 如果是有效數字且在範圍內返回True，否則返回False
    """
    try:
        num = float(value)
        
        # 檢查範圍
        if min_val is not None and num < min_val:
            return False
        if max_val is not None and num > max_val:
            return False
        
        return True
    except (ValueError, TypeError):
        return False

def is_valid_integer(value: str, min_val: Optional[int] = None, max_val: Optional[int] = None) -> bool:
    """
    驗證字符串是否為有效整數，並檢查範圍
    
    參數:
        value (str): 要驗證的字符串
        min_val (Optional[int]): 最小值限制，默認為None表示不限制
        max_val (Optional[int]): 最大值限制，默認為None表示不限制
        
    返回:
        bool: 如果是有效整數且在範圍內返回True，否則返回False
    """
    try:
        # 先檢查是否可以轉換為浮點數
        num = float(value)
        
        # 檢查是否為整數
        if num != int(num):
            return False
        
        # 轉換為整數
        num = int(num)
        
        # 檢查範圍
        if min_val is not None and num < min_val:
            return False
        if max_val is not None and num > max_val:
            return False
        
        return True
    except (ValueError, TypeError):
        return False

def is_valid_email(email: str) -> bool:
    """
    驗證電子郵件地址格式
    
    參數:
        email (str): 要驗證的電子郵件地址
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def is_valid_url(url: str) -> bool:
    """
    驗證URL格式
    
    參數:
        url (str): 要驗證的URL
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))

def is_valid_interface_name(name: str) -> bool:
    """
    驗證網絡接口名稱格式
    
    參數:
        name (str): 要驗證的網絡接口名稱
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    # 接口名稱格式的正則表達式
    pattern = r'^[a-zA-Z0-9]+([-_][a-zA-Z0-9]+)*(\d+)?$'
    return bool(re.match(pattern, name))

def validate_ssh_key_file(path: str) -> bool:
    """
    驗證SSH密鑰文件
    
    參數:
        path (str): 密鑰文件路徑
        
    返回:
        bool: 如果是有效的SSH密鑰文件返回True，否則返回False
    """
    # 檢查文件是否存在
    if not os.path.isfile(path):
        return False
    
    # 檢查文件權限（僅在Unix系統上）
    if os.name == 'posix':
        # 檢查文件權限是否過於寬鬆 (應為600或400)
        file_mode = os.stat(path).st_mode & 0o777
        if file_mode > 0o600:
            return False
    
    # 基本內容檢查
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read(100)  # 只讀取前100個字符進行檢查
            
            # 檢查是否是常見的私鑰格式
            if ('BEGIN RSA PRIVATE KEY' in content or
                'BEGIN PRIVATE KEY' in content or
                'BEGIN OPENSSH PRIVATE KEY' in content or
                'BEGIN DSA PRIVATE KEY' in content or
                'BEGIN EC PRIVATE KEY' in content):
                return True
        
        return False
    except Exception:
        return False

def is_valid_json(json_str: str) -> bool:
    """
    驗證JSON字符串格式
    
    參數:
        json_str (str): 要驗證的JSON字符串
        
    返回:
        bool: 如果格式正確返回True，否則返回False
    """
    import json
    try:
        json.loads(json_str)
        return True
    except json.JSONDecodeError:
        return False

def has_required_fields(data: Dict[str, Any], required_fields: List[str]) -> bool:
    """
    檢查字典是否包含所有必需字段
    
    參數:
        data (Dict[str, Any]): 要檢查的字典
        required_fields (List[str]): 必需字段列表
        
    返回:
        bool: 如果包含所有必需字段返回True，否則返回False
    """
    return all(field in data for field in required_fields)

def is_valid_ip_range(start_ip: str, end_ip: str) -> bool:
    """
    驗證IP地址範圍
    
    參數:
        start_ip (str): 起始IP地址
        end_ip (str): 結束IP地址
        
    返回:
        bool: 如果範圍有效返回True，否則返回False
    """
    if not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
        return False
    
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        return start <= end
    except ValueError:
        return False

def is_valid_log_level(level: str) -> bool:
    """
    驗證日誌級別
    
    參數:
        level (str): 日誌級別名稱
        
    返回:
        bool: 如果是有效的日誌級別返回True，否則返回False
    """
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL",
                   "調試", "信息", "警告", "錯誤", "嚴重"}
    return level.upper() in valid_levels or level in valid_levels

def is_non_negative_integer(value: str) -> bool:
    """
    檢查是否為非負整數
    
    參數:
        value (str): 要檢查的值
        
    返回:
        bool: 如果是非負整數返回True，否則返回False
    """
    return is_valid_integer(value, min_val=0)

def is_positive_integer(value: str) -> bool:
    """
    檢查是否為正整數
    
    參數:
        value (str): 要檢查的值
        
    返回:
        bool: 如果是正整數返回True，否則返回False
    """
    return is_valid_integer(value, min_val=1)