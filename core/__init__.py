#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 核心模組初始化
提供基礎功能實現的模組集合

此模組集合包含:
1. SSH客戶端連接管理
2. IP地址配置操作
3. 配置檔案管理
4. 異常處理機制
"""

# 定義公開的API
__all__ = [
    'SSHClient',
    'IPManager',
    'ConfigManager',
    'BaseAppError',
    'SSHConnectionError',
    'IPConfigError',
    'ValidationError',
    'ConfigError'
]

# 導入核心組件
from .ssh_client import SSHClient
from .ip_manager import IPManager
from .config_manager import ConfigManager
from .exceptions import (
    BaseAppError,
    SSHConnectionError,
    IPConfigError,
    ValidationError,
    ConfigError
)