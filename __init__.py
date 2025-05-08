#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 自動添加副IP到遠程Linux雲機的圖形化應用程序
根套件初始化模組

此模組定義套件元數據並提供項目版本信息。
"""

__version__ = '1.0.0'
__author__ = 'Your Name'
__email__ = 'your.email@example.com'
__license__ = 'MIT'
__description__ = '自動添加副IP到遠程Linux雲機的圖形化應用程序'

# 定義公開的API
__all__ = [
    'core',
    'gui',
    'utils',
    '__version__',
    '__author__',
    '__email__',
]

# 確保子套件可被直接從根套件導入
# 例如: from ssh_ip_adder import core
from . import core
from . import gui
from . import utils