#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 配置管理模塊
負責管理應用程序的配置信息

功能:
1. 加載和保存配置文件
2. 提供設置存取接口
3. 管理用戶偏好設置
4. 維護連接歷史記錄
"""

import os
import json
import logging
import time
import shutil  # 添加用於文件操作
from typing import Dict, List, Any, Optional, Union
from collections import OrderedDict

from .exceptions import ConfigError

# 獲取模塊級別日誌記錄器
logger = logging.getLogger("SSHIPAdder.Core.ConfigManager")

class ConfigManager:
    """
    配置管理類，負責應用程序配置的讀取和保存
    
    功能:
    1. 讀取/寫入JSON格式的配置文件
    2. 處理不同類型的配置項
    3. 管理連接歷史記錄
    4. 提供配置默認值
    """
    
    # 默認配置
    DEFAULT_CONFIG = {
        # 連接設置
        "server": "",
        "port": 22,
        "username": "",
        "use_key": False,
        "key_path": "",
        "save_password": False,
        "auto_connect": False,
        "connection_timeout": 10,
        "connection_retry": 1,
        
        # IP設置
        "default_netmask": "255.255.255.0 (/24)",
        "auto_interface": True,
        
        # 界面設置
        "theme": "系統默認",
        "font_size": 9,
        
        # 日誌設置
        "log_level": "信息",
        "save_log": True,
        "log_size": 1,
        
        # 高級設置
        "cmd_timeout": 30,
        "confirm_settings": True,
        "backup_config": True,
        
        # 連接歷史
        "recent_connections": []
    }
    
    # 最大歷史記錄數
    MAX_HISTORY_SIZE = 10
    
    def __init__(self, config_file: str):
        """
        初始化配置管理器
        
        參數:
            config_file (str): 配置文件路徑
        """
        self.config_file = config_file
        self.config = {}
        
        # 確保配置文件目錄存在
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        
        # 初始化配置
        self._init_config()
        
        logger.debug(f"配置管理器初始化完成，配置文件: {config_file}")
    
    def _init_config(self) -> None:
        """
        初始化配置文件
        
        如果配置文件不存在，則創建默認配置；
        如果存在，則加載現有配置。
        """
        try:
            if not os.path.exists(self.config_file):
                # 創建默認配置
                try:
                    with open(self.config_file, 'w', encoding='utf-8') as f:
                        json.dump(self.DEFAULT_CONFIG, f, ensure_ascii=False, indent=4)
                    
                    self.config = self.DEFAULT_CONFIG.copy()
                    logger.info(f"已創建默認配置文件: {self.config_file}")
                    
                except Exception as e:
                    logger.error(f"創建默認配置文件失敗: {str(e)}")
                    self.config = self.DEFAULT_CONFIG.copy()
            else:
                # 加載現有配置，如果失敗則使用默認配置
                try:
                    self.load_config()
                except ConfigError as e:
                    logger.warning(f"加載配置失敗 ({str(e)})，將使用默認配置")
                    self.config = self.DEFAULT_CONFIG.copy()
                    # 備份損壞的配置文件
                    self._backup_corrupted_config()
                    # 重新創建默認配置文件
                    with open(self.config_file, 'w', encoding='utf-8') as f:
                        json.dump(self.DEFAULT_CONFIG, f, ensure_ascii=False, indent=4)
        except Exception as e:
            # 保證即使發生異常，配置仍然被正確初始化
            logger.error(f"配置初始化過程中發生未知錯誤: {str(e)}")
            self.config = self.DEFAULT_CONFIG.copy()
    
    def _backup_corrupted_config(self) -> str:
        """
        備份損壞的配置文件
        
        返回:
            str: 備份文件路徑
        """
        try:
            timestamp = int(time.time())
            backup_path = f"{self.config_file}.corrupted.{timestamp}.bak"
            
            # 複製原配置文件
            shutil.copy2(self.config_file, backup_path)
            logger.info(f"已備份損壞的配置文件到: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"備份損壞配置文件失敗: {str(e)}")
            return ""

    def load_config(self) -> Dict[str, Any]:
        """
        加載配置文件
        
        返回:
            Dict[str, Any]: 配置字典
            
        異常:
            ConfigError: 加載配置失敗時抛出
        """
        if not os.path.exists(self.config_file):
            logger.warning(f"配置文件不存在: {self.config_file}")
            self._init_config()
            return self.config
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                file_content = f.read().strip()
                
                # 檢查文件是否為空
                if not file_content:
                    logger.warning("配置文件為空，將使用默認配置")
                    self.config = self.DEFAULT_CONFIG.copy()
                    return self.config
                
                # 嘗試解析JSON
                loaded_config = json.loads(file_content)
            
            # 使用默認配置填充缺失的項
            merged_config = self.DEFAULT_CONFIG.copy()
            if isinstance(loaded_config, dict):
                merged_config.update(loaded_config)
            else:
                logger.error("配置文件格式錯誤：不是有效的JSON對象")
                raise ConfigError("配置文件格式錯誤：不是有效的JSON對象", 402)
            
            self.config = merged_config
            logger.debug("成功加載配置文件")
            return self.config
            
        except json.JSONDecodeError as e:
            logger.error(f"配置文件格式錯誤: {str(e)}")
            raise ConfigError(f"配置文件格式錯誤: {str(e)}", 402)
            
        except Exception as e:
            logger.error(f"加載配置文件失敗: {str(e)}")
            raise ConfigError(f"加載配置文件失敗: {str(e)}", 400)
    
    def save_config(self, new_config: Dict[str, Any] = None) -> bool:
        """
        保存配置到文件
        
        參數:
            new_config (Dict[str, Any], optional): 要保存的新配置字典，
                                                   如果為None則保存當前配置
            
        返回:
            bool: 保存成功返回True，失敗抛出異常
            
        異常:
            ConfigError: 保存配置失敗時抛出
        """
        if new_config is not None:
            # 合併配置
            self.config.update(new_config)
        
        try:
            # 創建備份
            self.create_backup()
            
            # 先寫入臨時文件，然後再重命名，避免文件損壞
            temp_file = f"{self.config_file}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
            
            # 替換原文件
            os.replace(temp_file, self.config_file)
            
            logger.debug("成功保存配置文件")
            return True
            
        except Exception as e:
            logger.error(f"保存配置文件失敗: {str(e)}")
            raise ConfigError(f"保存配置文件失敗: {str(e)}", 400)
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """
        獲取配置值
        
        參數:
            key (str): 配置鍵名，支持點號分隔的嵌套鍵，如 "settings.log_level"
            default (Any, optional): 默認值，如果鍵不存在則返回此值
            
        返回:
            Any: 配置值或默認值
        """
        # 支持嵌套鍵，如 "settings.log_level"
        if '.' in key:
            parts = key.split('.')
            value = self.config
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return default
            return value
        
        # 直接鍵
        return self.config.get(key, default)
    
    def set_value(self, key: str, value: Any) -> bool:
        """
        設置配置值
        
        參數:
            key (str): 配置鍵名，支持點號分隔的嵌套鍵
            value (Any): 配置值
            
        返回:
            bool: 設置成功返回True，失敗返回False
        """
        try:
            # 支持嵌套鍵，如 "settings.log_level"
            if '.' in key:
                parts = key.split('.')
                config = self.config
                for part in parts[:-1]:
                    if part not in config:
                        config[part] = {}
                    config = config[part]
                config[parts[-1]] = value
            else:
                # 直接鍵
                self.config[key] = value
            
            # 保存配置
            self.save_config()
            logger.debug(f"已設置配置項: {key} = {value}")
            return True
            
        except Exception as e:
            logger.error(f"設置配置項失敗: {key} = {value}, 錯誤: {str(e)}")
            return False
    
    def remove_value(self, key: str) -> bool:
        """
        移除配置項
        
        參數:
            key (str): 配置鍵名，支持點號分隔的嵌套鍵
            
        返回:
            bool: 移除成功返回True，失敗或鍵不存在返回False
        """
        try:
            # 支持嵌套鍵，如 "settings.log_level"
            if '.' in key:
                parts = key.split('.')
                config = self.config
                for part in parts[:-1]:
                    if part not in config:
                        return False
                    config = config[part]
                
                if parts[-1] in config:
                    del config[parts[-1]]
                else:
                    return False
            else:
                # 直接鍵
                if key in self.config:
                    del self.config[key]
                else:
                    return False
            
            # 保存配置
            self.save_config()
            logger.debug(f"已移除配置項: {key}")
            return True
            
        except Exception as e:
            logger.error(f"移除配置項失敗: {key}, 錯誤: {str(e)}")
            return False
    
    def add_recent_connection(self, connection_info: Dict[str, Any]) -> bool:
        """
        添加最近連接記錄
        
        如果連接已存在於歷史記錄中，則更新該記錄並將其移至列表頂部。
        如果不存在，則添加到列表頂部。
        如果歷史記錄超過最大數量，則刪除最舊的記錄。
        
        參數:
            connection_info (Dict[str, Any]): 連接信息字典，至少包含
                                             server, port, username 字段
            
        返回:
            bool: 添加成功返回True，失敗返回False
        """
        # 驗證必要字段
        required_fields = ["server", "port", "username"]
        for field in required_fields:
            if field not in connection_info:
                logger.error(f"連接信息缺少必要字段: {field}")
                return False
        
        try:
            # 獲取現有歷史記錄
            recent_connections = self.config.get("recent_connections", [])
            
            # 確保recent_connections是列表類型
            if not isinstance(recent_connections, list):
                recent_connections = []
                logger.warning("recent_connections不是列表類型，已重置為空列表")
            
            # 檢查是否已存在相同的連接
            updated = False
            for i, conn in enumerate(recent_connections):
                if not isinstance(conn, dict):
                    continue
                    
                if (conn.get("server") == connection_info.get("server") and
                    conn.get("port") == connection_info.get("port") and
                    conn.get("username") == connection_info.get("username")):
                    # 更新現有連接並移至列表頂部
                    recent_connections.pop(i)
                    recent_connections.insert(0, connection_info)
                    updated = True
                    break
            
            if not updated:
                # 添加新連接到列表頂部
                recent_connections.insert(0, connection_info)
            
            # 限制最近連接的數量
            if len(recent_connections) > self.MAX_HISTORY_SIZE:
                recent_connections = recent_connections[:self.MAX_HISTORY_SIZE]
            
            # 更新配置
            self.config["recent_connections"] = recent_connections
            self.save_config()
            
            logger.debug(f"已添加最近連接: {connection_info.get('username')}@{connection_info.get('server')}:{connection_info.get('port')}")
            return True
            
        except Exception as e:
            logger.error(f"添加最近連接記錄失敗: {str(e)}")
            return False
    
    def get_recent_connections(self) -> List[Dict[str, Any]]:
        """
        獲取最近連接記錄
        
        返回:
            List[Dict[str, Any]]: 最近連接記錄列表
        """
        connections = self.config.get("recent_connections", [])
        # 確保返回的是列表並且每個元素都是字典
        if not isinstance(connections, list):
            return []
        return [conn for conn in connections if isinstance(conn, dict)]
    
    def clear_recent_connections(self) -> bool:
        """
        清空最近連接記錄
        
        返回:
            bool: 清空成功返回True，失敗返回False
        """
        try:
            self.config["recent_connections"] = []
            self.save_config()
            
            logger.debug("已清空最近連接記錄")
            return True
            
        except Exception as e:
            logger.error(f"清空最近連接記錄失敗: {str(e)}")
            return False
    
    def export_config(self, export_file: str) -> bool:
        """
        導出配置到文件
        
        參數:
            export_file (str): 導出文件路徑
            
        返回:
            bool: 導出成功返回True，失敗返回False
        """
        try:
            # 創建要導出的配置副本
            export_config = self.config.copy()
            
            # 移除敏感信息
            if "password" in export_config:
                del export_config["password"]
            
            # 寫入文件
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_config, f, ensure_ascii=False, indent=4)
            
            logger.debug(f"已導出配置到文件: {export_file}")
            return True
            
        except Exception as e:
            logger.error(f"導出配置失敗: {str(e)}")
            return False
    
    def import_config(self, import_file: str) -> bool:
        """
        從文件導入配置
        
        參數:
            import_file (str): 導入文件路徑
            
        返回:
            bool: 導入成功返回True，失敗返回False
        """
        try:
            # 讀取導入文件
            with open(import_file, 'r', encoding='utf-8') as f:
                import_config = json.load(f)
            
            # 確保導入的是有效的配置
            if not isinstance(import_config, dict):
                logger.error("導入的配置格式無效")
                return False
            
            # 保留現有的敏感信息
            if "password" in self.config and self.config.get("save_password", False):
                import_config["password"] = self.config["password"]
            
            # 保留現有的連接歷史
            if "recent_connections" in self.config:
                import_config["recent_connections"] = self.config["recent_connections"]
            
            # 更新配置
            self.config.update(import_config)
            self.save_config()
            
            logger.debug(f"已從文件導入配置: {import_file}")
            return True
            
        except json.JSONDecodeError:
            logger.error("導入文件格式錯誤")
            return False
            
        except Exception as e:
            logger.error(f"導入配置失敗: {str(e)}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """
        重置配置到默認值
        
        返回:
            bool: 重置成功返回True，失敗返回False
        """
        try:
            # 保留連接歷史
            recent_connections = self.config.get("recent_connections", [])
            
            # 重置為默認配置
            self.config = self.DEFAULT_CONFIG.copy()
            
            # 恢復連接歷史
            self.config["recent_connections"] = recent_connections
            
            # 保存配置
            self.save_config()
            
            logger.debug("已重置配置到默認值")
            return True
            
        except Exception as e:
            logger.error(f"重置配置失敗: {str(e)}")
            return False
    
    def get_log_level(self) -> int:
        """
        獲取日誌級別對應的logging模塊級別值
        
        返回:
            int: logging模塊的日誌級別常量
        """
        # 配置中的日誌級別名稱映射到logging模塊的級別
        level_map = {
            "調試": logging.DEBUG,
            "信息": logging.INFO,
            "警告": logging.WARNING,
            "錯誤": logging.ERROR,
            "嚴重": logging.CRITICAL
        }
        
        # 獲取配置中的日誌級別
        log_level_name = self.get_value("log_level", "信息")
        
        # 返回映射後的日誌級別，默認為INFO
        return level_map.get(log_level_name, logging.INFO)
    
    def create_backup(self) -> str:
        """
        創建配置文件的備份
        
        返回:
            str: 備份文件路徑，失敗返回空字符串
        """
        try:
            # 確保文件存在
            if not os.path.exists(self.config_file):
                return ""
                
            # 生成備份文件名
            backup_dir = os.path.dirname(self.config_file)
            file_name = os.path.basename(self.config_file)
            timestamp = time.strftime("%Y%m%d%H%M%S")
            backup_file = os.path.join(backup_dir, f"{file_name}.{timestamp}.bak")
            
            # 創建備份
            shutil.copy2(self.config_file, backup_file)
            
            logger.debug(f"已創建配置備份: {backup_file}")
            return backup_file
            
        except Exception as e:
            logger.error(f"創建配置備份失敗: {str(e)}")
            return ""
    
    def restore_backup(self, backup_file: str) -> bool:
        """
        從備份文件恢復配置
        
        參數:
            backup_file (str): 備份文件路徑
            
        返回:
            bool: 恢復成功返回True，失敗返回False
        """
        if not os.path.exists(backup_file):
            logger.error(f"備份文件不存在: {backup_file}")
            return False
        
        try:
            # 先創建當前配置的備份
            current_backup = self.create_backup()
            
            # 恢復配置
            shutil.copy2(backup_file, self.config_file)
            
            # 重新加載配置
            self.load_config()
            
            logger.debug(f"已從備份恢復配置: {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"從備份恢復配置失敗: {str(e)}")
            
            # 嘗試回滾到之前的配置
            if current_backup and os.path.exists(current_backup):
                try:
                    shutil.copy2(current_backup, self.config_file)
                    
                    # 重新加載配置
                    self.load_config()
                    logger.debug("已回滾到之前的配置")
                except Exception:
                    logger.error("回滾到之前的配置失敗")
            
            return False
    
    def get_backup_list(self) -> List[str]:
        """
        獲取可用的配置備份文件列表
        
        返回:
            List[str]: 備份文件路徑列表
        """
        try:
            backup_dir = os.path.dirname(self.config_file)
            file_name = os.path.basename(self.config_file)
            
            # 查找所有備份文件
            backup_files = []
            for f in os.listdir(backup_dir):
                if f.startswith(file_name) and f.endswith(".bak"):
                    backup_files.append(os.path.join(backup_dir, f))
            
            # 按修改時間排序，最新的在前
            backup_files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
            
            return backup_files
            
        except Exception as e:
            logger.error(f"獲取備份列表失敗: {str(e)}")
            return []
    
    def get_all_config(self) -> Dict[str, Any]:
        """
        獲取完整配置
        
        返回:
            Dict[str, Any]: 完整配置字典的副本
        """
        return self.config.copy()
    
    def merge_config(self, new_config: Dict[str, Any]) -> bool:
        """
        合併新配置到當前配置
        
        參數:
            new_config (Dict[str, Any]): 要合併的新配置
            
        返回:
            bool: 合併成功返回True，失敗返回False
        """
        try:
            # 遞歸合併配置
            self._recursive_merge(self.config, new_config)
            
            # 保存配置
            self.save_config()
            
            logger.debug("已合併新配置")
            return True
            
        except Exception as e:
            logger.error(f"合併配置失敗: {str(e)}")
            return False
    
    def _recursive_merge(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        遞歸合併字典
        
        參數:
            target (Dict[str, Any]): 目標字典
            source (Dict[str, Any]): 源字典
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                # 如果兩個都是字典，遞歸合併
                self._recursive_merge(target[key], value)
            else:
                # 否則直接替換
                target[key] = value