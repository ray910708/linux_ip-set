#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 工具模組初始化
提供各種通用功能輔助函數

此模組集合包含:
1. 網絡工具函數
2. 數據驗證工具
3. 系統操作輔助函數
4. 日誌與調試工具
"""

# 定義公開的API
__all__ = [
    # 網絡工具函數
    'validate_ip', 
    'validate_ip_cidr',
    'cidr_to_netmask',
    'netmask_to_cidr',
    'get_ip_range',
    
    # 數據驗證函數
    'is_valid_ip',
    'is_valid_hostname',
    'is_valid_port',
    'is_valid_netmask',
    'is_valid_mac',
    'is_valid_file_path'
]

# 導入網絡工具函數
from .network_utils import (
    validate_ip,
    validate_ip_cidr,
    cidr_to_netmask,
    netmask_to_cidr,
    get_ip_range,
    get_network_info,
    generate_ip_addresses,
    is_ip_in_network
)

# 導入驗證工具函數
from .validators import (
    is_valid_ip,
    is_valid_ip_cidr,
    is_valid_hostname,
    is_valid_port,
    is_valid_netmask,
    is_valid_mac,
    is_valid_file_path,
    is_valid_dir_path,
    is_valid_file_permission
)