#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: GUI資源模組初始化
管理界面資源文件的加載與訪問

此模組提供訪問圖標、樣式表等靜態資源的統一接口，
支持跨平台資源路徑解析。
"""

import os

# 定義資源路徑常量
RESOURCES_DIR = os.path.dirname(os.path.abspath(__file__))
ICONS_DIR = os.path.join(RESOURCES_DIR, 'icons')
STYLES_DIR = os.path.join(RESOURCES_DIR, 'styles')

# 資源文件路徑解析函數
def get_resource_path(relative_path: str) -> str:
    """
    解析資源文件的絕對路徑
    
    參數:
        relative_path (str): 相對於資源目錄的路徑
        
    返回:
        str: 資源文件的絕對路徑
    """
    return os.path.join(RESOURCES_DIR, relative_path)

def get_icon_path(icon_name: str) -> str:
    """
    解析圖標文件的絕對路徑
    
    參數:
        icon_name (str): 圖標文件名
        
    返回:
        str: 圖標文件的絕對路徑
    """
    return os.path.join(ICONS_DIR, icon_name)

# 定義公開的API
__all__ = [
    'RESOURCES_DIR',
    'ICONS_DIR',
    'STYLES_DIR',
    'get_resource_path',
    'get_icon_path'
]