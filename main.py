#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 自動添加副IP到遠程Linux雲機的圖形化應用程序
主程序入口

此模塊作為應用程序的啟動入口，負責:
1. 配置日誌系統
2. 初始化應用程序環境
3. 創建並顯示主窗口
4. 處理應用程序級別的異常
"""

import sys
import os
import logging
import argparse
import traceback
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
import logging.handlers

# 將專案根目錄加入 sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# 模塊版本與元數據
__version__ = '1.0.0'
__author__ = 'Your Name'
__email__ = 'your.email@example.com'

# 設置應用程序的基本路徑
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 導入本地模塊
try:
    # 嘗試直接導入
    from gui.main_window import MainWindow
    from core.config_manager import ConfigManager
    from core.exceptions import BaseAppError
    print("成功直接導入模塊")
except ImportError as e:
    print(f"直接導入失敗: {e}")
    try:
        # 如果在gui/main_window.py中使用相對導入，先將當前目錄設置為包
        if os.path.basename(BASE_DIR) == 'ssh_ip_adder':
            package_name = os.path.basename(BASE_DIR)
            if package_name not in sys.modules:
                import importlib.util
                spec = importlib.util.spec_from_file_location(package_name, os.path.join(BASE_DIR, "__init__.py"))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[package_name] = module
                    spec.loader.exec_module(module)
                    print(f"已將 {package_name} 設置為包")
        
        # 嘗試使用絕對導入
        from ssh_ip_adder.gui.main_window import MainWindow
        from ssh_ip_adder.core.config_manager import ConfigManager
        from ssh_ip_adder.core.exceptions import BaseAppError
        print("成功使用絕對導入")
    except ImportError as e:
        # 顯示詳細的錯誤信息和路徑
        print(f"所有導入方式均失敗: {e}")
        print(f"當前目錄: {os.getcwd()}")
        print(f"BASE_DIR: {BASE_DIR}")
        print(f"Python路徑: {sys.path}")
        print("嘗試檢查gui/main_window.py中的導入方式...")
        gui_init_path = os.path.join(BASE_DIR, "gui", "__init__.py")
        if os.path.exists(gui_init_path):
            with open(gui_init_path, 'r', encoding='utf-8') as f:
                print(f"gui/__init__.py內容:\n{f.read()}")
        main_window_path = os.path.join(BASE_DIR, "gui", "main_window.py")
        if os.path.exists(main_window_path):
            with open(main_window_path, 'r', encoding='utf-8') as f:
                first_lines = ''.join(f.readlines()[:50])
                print(f"gui/main_window.py前幾行:\n{first_lines}")
        raise

def setup_logging(verbose=False):
    """
    配置應用程序的日誌系統
    
    參數:
        verbose (bool): 是否啟用詳細日誌
    """
    # 確定日誌級別
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # 確保日誌目錄存在
    app_data_dir = get_app_data_dir()
    log_dir = os.path.join(app_data_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # 配置日誌處理器
    log_file = os.path.join(log_dir, 'ssh_ip_adder.log')
    
    # 配置根日誌記錄器
    logger = logging.getLogger('SSHIPAdder')
    logger.setLevel(log_level)
    
    # 文件處理器 - 滾動日誌，最多保留5個備份，每個最大1MB
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=1024*1024, backupCount=5, encoding='utf-8'
    )
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # 控制台處理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    
    # 添加處理器到根日誌記錄器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # 設置未捕獲異常的處理器
    sys.excepthook = handle_exception
    
    return logger

def handle_exception(exc_type, exc_value, exc_traceback):
    """
    處理未捕獲的異常
    
    參數:
        exc_type: 異常類型
        exc_value: 異常值
        exc_traceback: 異常堆棧跟蹤
    """
    # 忽略KeyboardInterrupt異常的詳細堆棧
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    # 獲取日誌記錄器
    logger = logging.getLogger('SSHIPAdder')
    
    # 格式化異常信息
    exception_message = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    
    # 記錄異常
    logger.critical(f"未捕獲的異常:\n{exception_message}")
    
    # 如果有GUI實例，顯示錯誤對話框
    if QApplication.instance():
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setWindowTitle("應用程序錯誤")
        error_box.setText("應用程序發生了未處理的錯誤")
        error_box.setDetailedText(exception_message)
        error_box.setStandardButtons(QMessageBox.Ok)
        error_box.exec_()

def get_app_data_dir():
    """
    獲取應用程序數據目錄
    
    返回:
        str: 應用程序數據目錄的路徑
    """
    # 根據操作系統確定應用數據目錄
    if sys.platform == 'win32':
        app_data = os.path.join(os.environ['APPDATA'], 'SSHIPAdder')
    elif sys.platform == 'darwin':
        app_data = os.path.expanduser('~/Library/Application Support/SSHIPAdder')
    else:
        app_data = os.path.expanduser('~/.ssh_ip_adder')
    
    # 確保目錄存在
    os.makedirs(app_data, exist_ok=True)
    
    return app_data

def setup_application():
    """
    設置應用程序環境
    
    返回:
        ConfigManager: 配置管理器實例
    """
    # 獲取應用程序數據目錄
    app_data_dir = get_app_data_dir()
    
    # 確保配置目錄存在
    config_dir = os.path.join(app_data_dir, 'config')
    os.makedirs(config_dir, exist_ok=True)
    
    # 初始化配置管理器
    config_path = os.path.join(config_dir, "config.json")
    
    # 記錄應用程序啟動
    logger = logging.getLogger('SSHIPAdder')
    logger.info(f"應用程序數據目錄: {app_data_dir}")
    
    try:
        # 初始化配置管理器
        config_manager = ConfigManager(config_path)
        logger.info("配置管理器初始化完成")
        return config_manager
    except ConfigError as e:
        # 配置錯誤，嘗試恢復
        logger.error(f"配置初始化錯誤: {str(e)}")
        # 備份損壞的配置文件
        if os.path.exists(config_path):
            backup_path = f"{config_path}.error.{int(time.time())}.bak"
            try:
                shutil.copy2(config_path, backup_path)
                logger.info(f"已備份損壞的配置文件到: {backup_path}")
            except Exception as be:
                logger.error(f"備份配置文件失敗: {str(be)}")
        
        # 重新創建新的配置管理器和默認配置文件
        try:
            # 刪除損壞的配置文件
            if os.path.exists(config_path):
                os.remove(config_path)
            # 重新創建配置管理器，會自動創建新的默認配置
            config_manager = ConfigManager(config_path)
            logger.info("已重新創建配置管理器和默認配置")
            return config_manager
        except Exception as re:
            logger.critical(f"重新創建配置管理器失敗: {str(re)}")
            # 最後嘗試：創建一個僅使用內存中默認配置的配置管理器
            config_manager = ConfigManager(config_path)
            config_manager.config = config_manager.DEFAULT_CONFIG.copy()
            logger.warning("使用內存中的默認配置繼續運行")
            return config_manager
    except Exception as e:
        # 處理其他異常
        logger.critical(f"配置管理器初始化過程中發生未預期的錯誤: {str(e)}")
        # 創建一個僅使用內存中默認配置的配置管理器
        config_manager = ConfigManager(config_path)
        config_manager.config = config_manager.DEFAULT_CONFIG.copy()
        logger.warning("使用內存中的默認配置繼續運行")
        return config_manager

def parse_arguments():
    """
    解析命令行參數
    
    返回:
        Namespace: 解析後的參數對象
    """
    parser = argparse.ArgumentParser(description='SSH IP Adder - 自動添加副IP到遠程Linux雲機的工具')
    parser.add_argument('-v', '--verbose', action='store_true', help='啟用詳細日誌輸出')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    return parser.parse_args()

def main():
    """
    應用程序主入口函數
    """
    # 解析命令行參數
    args = parse_arguments()
    
    # 設置日誌系統
    logger = setup_logging(verbose=args.verbose)
    logger.info(f"啟動SSH-IP-Adder應用程序 v{__version__}")
    
    try:
        # 初始化應用程序
        app = QApplication(sys.argv)
        app.setApplicationName("SSH IP Adder")
        app.setApplicationDisplayName("SSH IP Adder")
        app.setApplicationVersion(__version__)
        
        # 設置應用程序樣式
        app.setStyle("Fusion")
        
        # 設置應用程序圖標（需替換為實際路徑）
        icon_path = os.path.join(BASE_DIR, "gui", "resources", "icons", "app_icon.png")
        if os.path.exists(icon_path):
            app.setWindowIcon(QIcon(icon_path))
        
        # 設置應用程序環境
        config_manager = setup_application()
        
        # 創建並顯示主窗口
        main_window = MainWindow(config_manager)
        main_window.show()
        
        # 運行應用程序主循環
        sys.exit(app.exec_())
        
    except BaseAppError as e:
        # 處理應用程序級別的異常
        logger.error(f"應用程序錯誤: {str(e)}")
        if QApplication.instance():
            QMessageBox.critical(None, "應用程序錯誤", str(e))
        sys.exit(1)
        
    except Exception as e:
        # 處理意外異常
        logger.critical(f"未預期的錯誤: {str(e)}")
        if QApplication.instance():
            QMessageBox.critical(None, "未預期的錯誤", str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()