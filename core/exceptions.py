#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 異常處理模塊
定義應用程序中使用的各種異常類

階層結構:
1. BaseAppError - 基礎異常類
   ├── SSHConnectionError - SSH連接相關異常
   ├── IPConfigError - IP配置相關異常
   ├── ValidationError - 數據驗證異常
   └── ConfigError - 配置文件處理異常
"""

class BaseAppError(Exception):
    """
    應用程序基礎異常類
    
    所有自定義異常的基類，提供統一的消息格式和處理機制。
    
    屬性:
        message (str): 異常消息
        code (int): 錯誤代碼，默認為0
    """
    
    def __init__(self, message: str, code: int = 0):
        """
        初始化基礎異常
        
        參數:
            message (str): 異常消息
            code (int, optional): 錯誤代碼，默認為0
        """
        self.message = message
        self.code = code
        super().__init__(self.message)
    
    def __str__(self) -> str:
        """
        返回異常的字符串表示
        
        返回:
            str: 格式化的異常消息
        """
        if self.code:
            return f"[錯誤 {self.code}] {self.message}"
        return self.message


class SSHConnectionError(BaseAppError):
    """
    SSH連接相關異常
    
    當SSH連接建立、維護或操作過程中發生錯誤時抛出。
    
    錯誤代碼範圍: 100-199
    - 100: 一般連接錯誤
    - 101: 認證失敗
    - 102: 網絡錯誤
    - 103: 超時錯誤
    - 104: 主機不可達
    - 105: 命令執行錯誤
    """
    
    def __init__(self, message: str, code: int = 100):
        """
        初始化SSH連接異常
        
        參數:
            message (str): 異常消息
            code (int, optional): 錯誤代碼，默認為100
        """
        super().__init__(message, code)


class IPConfigError(BaseAppError):
    """
    IP配置相關異常
    
    當IP地址配置、修改或刪除過程中發生錯誤時抛出。
    
    錯誤代碼範圍: 200-299
    - 200: 一般IP配置錯誤
    - 201: 無效的IP格式
    - 202: IP已存在
    - 203: IP不存在
    - 204: 網卡不存在
    - 205: 網卡未啟用
    - 206: 配置持久化失敗
    - 207: DHCP轉換錯誤
    """
    
    def __init__(self, message: str, code: int = 200):
        """
        初始化IP配置異常
        
        參數:
            message (str): 異常消息
            code (int, optional): 錯誤代碼，默認為200
        """
        super().__init__(message, code)


class ValidationError(BaseAppError):
    """
    數據驗證異常
    
    當輸入數據驗證失敗時抛出。
    
    錯誤代碼範圍: 300-399
    - 300: 一般驗證錯誤
    - 301: 必要參數缺失
    - 302: 參數類型錯誤
    - 303: 參數範圍錯誤
    - 304: 格式錯誤
    """
    
    def __init__(self, message: str, code: int = 300):
        """
        初始化數據驗證異常
        
        參數:
            message (str): 異常消息
            code (int, optional): 錯誤代碼，默認為300
        """
        super().__init__(message, code)


class ConfigError(BaseAppError):
    """
    配置文件處理異常
    
    當配置文件讀取、解析或保存過程中發生錯誤時抛出。
    
    錯誤代碼範圍: 400-499
    - 400: 一般配置錯誤
    - 401: 配置文件不存在
    - 402: 配置文件格式錯誤
    - 403: 配置文件訪問權限錯誤
    - 404: 配置項缺失
    - 405: 配置項類型錯誤
    """
    
    def __init__(self, message: str, code: int = 400):
        """
        初始化配置文件處理異常
        
        參數:
            message (str): 異常消息
            code (int, optional): 錯誤代碼，默認為400
        """
        super().__init__(message, code)