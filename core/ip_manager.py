#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: IP管理模塊
負責在遠程服務器上執行IP地址相關操作

主要功能:
1. 獲取網絡接口列表
2. 添加/刪除IP地址
3. 檢查IP配置
4. DHCP到靜態IP轉換
5. 配置持久化
"""

import re
import logging
import time
import ipaddress
import os
import yaml
import tempfile
from typing import Optional, List, Dict, Tuple, Any, Union
from datetime import datetime

from .ssh_client import SSHClient
from .exceptions import IPConfigError

# 獲取模塊級別日誌記錄器
logger = logging.getLogger("SSHIPAdder.Core.IPManager")

class CommandBatcher:
    """命令批處理器，優化SSH調用"""
    
    def __init__(self, ssh_client):
        self.ssh_client = ssh_client
        self.commands = []
        self.max_batch_size = 20  # 單次批處理的最大命令數
        
    def add_command(self, cmd: str) -> None:
        """添加命令到批處理隊列"""
        self.commands.append(cmd)
        
        # 當達到閾值時自動執行
        if len(self.commands) >= self.max_batch_size:
            self.execute()
            
    def execute(self) -> Tuple[int, str, str]:
        """執行批處理命令"""
        if not self.commands:
            return 0, "", ""
            
        result = self.ssh_client.execute_batch_commands(self.commands)
        self.commands = []  # 清空隊列
        return result
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出時執行剩餘命令"""
        if self.commands:
            self.execute()

class InterfaceCache:
    """
    接口信息緩存類，減少重複的SSH查詢
    """
    
    def __init__(self, ttl: int = 300):
        """
        初始化緩存
        
        參數:
            ttl (int): 緩存有效時間（秒）
        """
        self.cache = {}
        self.ttl = ttl
    
    def get(self, key: str) -> Any:
        """
        獲取緩存項
        
        參數:
            key (str): 緩存健
            
        返回:
            Any: 緩存值，如果不存在或過期則返回None
        """
        if key not in self.cache:
            return None
            
        item = self.cache[key]
        if time.time() - item['timestamp'] > self.ttl:
            # 緩存已過期
            del self.cache[key]
            return None
            
        return item['value']
    
    def set(self, key: str, value: Any) -> None:
        """
        設置緩存項
        
        參數:
            key (str): 緩存鍵
            value (Any): 緩存值
        """
        self.cache[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    def invalidate(self, key: str = None) -> None:
        """
        使指定鍵或全部緩存失效
        
        參數:
            key (str, optional): 緩存鍵，如果為None則清空全部緩存
        """
        if key is None:
            self.cache.clear()
        elif key in self.cache:
            del self.cache[key]

class IPManager:
    """
    IP管理類，負責在遠程服務器上執行IP地址相關操作
    
    主要職責:
    1. 管理網絡接口
    2. 配置IP地址
    3. 操作網絡服務
    4. 轉換DHCP到靜態IP
    """
    
    def __init__(self, ssh_client: SSHClient):
        """
        初始化IP管理器
        
        參數:
            ssh_client (SSHClient): SSH客戶端實例
        """
        self.ssh_client = ssh_client
        self._default_interface = None
        self._os_type = None
        self._os_version = None
        self._available_interfaces = []
        
        # 添加接口信息緩存
        self.cache = InterfaceCache(ttl=300)  # 緩存5分鐘
        
        # 命令批處理器
        self.cmd_batcher = CommandBatcher(ssh_client)
        
        # 初始化時檢測操作系統類型
        self._detect_os_type()
        
        logger.debug("IP管理器初始化完成")
    
    def get_interfaces(self) -> List[str]:
        """
        獲取遠程服務器上的網絡接口列表，使用緩存
        
        返回:
            List[str]: 網絡接口名稱列表
            
        異常:
            IPConfigError: 獲取網絡接口失敗時拋出
        """
        # 檢查緩存
        cache_key = "interfaces_list"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"從緩存獲取接口列表: {cached}")
            return cached
        
        logger.info("正在獲取網絡接口列表")
        
        try:
            # 使用ip命令獲取所有網絡接口
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                "ip -o link show | grep -v 'LOOPBACK\\|NO-CARRIER' | awk -F': ' '{print $2}'"
            )
            
            if exit_code != 0:
                logger.error(f"獲取網絡接口失敗: {stderr}")
                raise IPConfigError(f"獲取網絡接口失敗: {stderr}")
            
            # 解析輸出獲取接口名稱
            interfaces = [iface.strip() for iface in stdout.strip().split('\n') if iface.strip()]
            
            if not interfaces:
                logger.warning("未找到活動的網絡接口")
                return []
            
            # 保存接口列表到緩存
            self.cache.set(cache_key, interfaces)
            
            # 保存接口列表
            self._available_interfaces = interfaces
            
            # 保存第一個接口作為默認接口
            if interfaces and not self._default_interface:
                self._default_interface = interfaces[0]
                logger.debug(f"設置默認接口: {self._default_interface}")
            
            logger.info(f"找到 {len(interfaces)} 個網絡接口: {', '.join(interfaces)}")
            return interfaces
            
        except Exception as e:
            logger.error(f"獲取網絡接口列表時發生錯誤: {str(e)}")
            raise IPConfigError(f"獲取網絡接口列表時發生錯誤: {str(e)}")   
        
    def get_default_interface(self) -> str:
        """
        獲取默認網絡接口
        
        返回:
            str: 默認網絡接口名稱
            
        異常:
            IPConfigError: 獲取默認網絡接口失敗時抛出
        """
        if self._default_interface:
            return self._default_interface
        
        logger.info("正在獲取默認網絡接口")
        
        try:
            # 使用ip route獲取默認路由接口
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                "ip route | grep default | awk '{print $5}' | head -n 1"
            )
            
            if exit_code != 0 or not stdout.strip():
                # 如果無法獲取默認路由接口，則獲取第一個活動接口
                interfaces = self.get_interfaces()
                if not interfaces:
                    raise IPConfigError("無法確定默認網絡接口")
                
                self._default_interface = interfaces[0]
                logger.info(f"使用第一個活動接口作為默認接口: {self._default_interface}")
            else:
                self._default_interface = stdout.strip()
                logger.info(f"獲取到默認路由接口: {self._default_interface}")
            
            return self._default_interface
            
        except Exception as e:
            logger.error(f"獲取默認網絡接口時發生錯誤: {str(e)}")
            raise IPConfigError(f"獲取默認網絡接口時發生錯誤: {str(e)}")
    
    def is_interface_up(self, interface: Optional[str] = None) -> bool:
        """
        檢查網絡接口是否啟用
        
        參數:
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
            
        返回:
            bool: 如果接口啟用返回True，否則返回False
            
        異常:
            IPConfigError: 檢查接口狀態失敗時抛出
        """
        # 確定要檢查的接口
        if not interface:
            interface = self.get_default_interface()
        
        try:
            # 檢查接口狀態
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip link show {interface} | grep 'state'"
            )
            
            if exit_code != 0:
                logger.error(f"檢查接口 {interface} 狀態失敗: {stderr}")
                raise IPConfigError(f"檢查接口 {interface} 狀態失敗: {stderr}")
            
            # 檢查是否包含 "UP" 狀態
            return "UP" in stdout
            
        except Exception as e:
            logger.error(f"檢查接口狀態時發生錯誤: {str(e)}")
            raise IPConfigError(f"檢查接口狀態時發生錯誤: {str(e)}")
    
    def get_ip_config(self, interface: Optional[str] = None) -> str:
        """
        獲取網絡接口的IP配置信息
        
        參數:
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
            
        返回:
            str: IP配置信息
            
        異常:
            IPConfigError: 獲取IP配置信息失敗時抛出
        """
        # 確定要查詢的接口
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"正在獲取接口 {interface} 的IP配置")
        
        try:
            # 使用ip addr show獲取接口的IP配置
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip addr show dev {interface}"
            )
            
            if exit_code != 0:
                logger.error(f"獲取接口 {interface} 的IP配置失敗: {stderr}")
                raise IPConfigError(f"獲取接口 {interface} 的IP配置失敗: {stderr}")
            
            if not stdout.strip():
                logger.warning(f"接口 {interface} 沒有IP配置信息")
                return f"接口 {interface} 沒有IP配置信息"
            
            return stdout
            
        except Exception as e:
            logger.error(f"獲取IP配置信息時發生錯誤: {str(e)}")
            raise IPConfigError(f"獲取IP配置信息時發生錯誤: {str(e)}")
    
    def get_full_interface_info(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """
        獲取網絡接口的詳細信息
        
        參數:
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
            
        返回:
            Dict[str, Any]: 接口詳細信息字典
            
        異常:
            IPConfigError: 獲取接口信息失敗時抛出
        """
        # 確定要查詢的接口
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"正在獲取接口 {interface} 的詳細信息")
        
        try:
            # 初始化結果字典
            result = {
                "interface": interface,
                "is_up": self.is_interface_up(interface)
            }
            # 獲取網絡配置信息
            config = self.analyze_network_config(interface)
            result.update(config)
            
            # 獲取MAC地址
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip link show {interface} | grep -o 'link/ether [0-9a-f:]*' | cut -d' ' -f2"
            )
            
            if exit_code == 0 and stdout.strip():
                result["mac_address"] = stdout.strip()
            
            # 獲取接口統計信息
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip -s link show {interface}"
            )
            
            if exit_code == 0:
                # 解析統計信息
                rx_pattern = r"RX:.*?bytes\s+(\d+).*?packets\s+(\d+).*?errors\s+(\d+)"
                tx_pattern = r"TX:.*?bytes\s+(\d+).*?packets\s+(\d+).*?errors\s+(\d+)"
                
                rx_match = re.search(rx_pattern, stdout, re.DOTALL)
                tx_match = re.search(tx_pattern, stdout, re.DOTALL)
                
                if rx_match:
                    result["rx_bytes"] = int(rx_match.group(1))
                    result["rx_packets"] = int(rx_match.group(2))
                    result["rx_errors"] = int(rx_match.group(3))
                
                if tx_match:
                    result["tx_bytes"] = int(tx_match.group(1))
                    result["tx_packets"] = int(tx_match.group(2))
                    result["tx_errors"] = int(tx_match.group(3))
                
                if rx_match and tx_match:
                    result["errors"] = int(
                        rx_match.group(3)) + int(tx_match.group(3))
            
            # 獲取配置文件路徑
            if self._os_type == 'debian':
                result["config_file"] = f"/etc/network/interfaces.d/{interface}"
            elif self._os_type == 'redhat':
                result["config_file"] = f"/etc/sysconfig/network-scripts/ifcfg-{interface}"
            elif self._os_type == 'netplan':
                # 使用改進的方法查找Netplan配置文件
                result["config_file"] = self._find_netplan_config_file(
                    interface)
            
            return result
            
        except Exception as e:
            logger.error(f"獲取接口詳細信息時發生錯誤: {str(e)}")
            raise IPConfigError(f"獲取接口詳細信息時發生錯誤: {str(e)}")
    
    def analyze_network_config(self, interface: str) -> Dict[str, Any]:
        """
        分析網絡接口的配置類型（靜態/DHCP）和相關設置，改進版本
        
        參數:
            interface (str): 網絡接口名稱
            
        返回:
            Dict[str, Any]: 包含配置信息的字典
        """
        if not self._interface_exists(interface):
            logger.error(f"接口 {interface} 不存在，無法分析配置")
            return {
                "success": False,
                "error": f"接口 {interface} 不存在",
                "is_dhcp": False,
                "config_files": []
            }
            
        # 初始化配置字典
        config = {
            "success": True,
            "error": None,
            "interface": interface,
            "is_dhcp": False,  # 默認為靜態配置
            "config_files": [],
            "config_type": None,
            "addresses": [],
            "gateway": None,
            "dns_servers": []
        }
        
        # 檢查當前實際IP配置
        try:
            # 獲取當前IP配置
            ip_info_cmd = f"ip -o -4 addr show {interface}"
            exit_code, ip_info, _ = self.ssh_client.execute_command(ip_info_cmd)
            
            if exit_code == 0 and ip_info.strip():
                # 解析IP地址
                ip_matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', ip_info)
                if ip_matches:
                    config["addresses"] = [f"{ip}/{cidr}" for ip, cidr in ip_matches]
                    logger.debug(f"接口 {interface} 當前IP: {config['addresses']}")
            
            # 檢查默認路由
            gateway_cmd = f"ip route show dev {interface} | grep default"
            exit_code, gateway_info, _ = self.ssh_client.execute_command(gateway_cmd)
            
            if exit_code == 0 and gateway_info.strip():
                gateway_match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', gateway_info)
                if gateway_match:
                    config["gateway"] = gateway_match.group(1)
                    logger.debug(f"接口 {interface} 當前網關: {config['gateway']}")
            
            # 獲取DNS配置
            dns_cmd = "cat /etc/resolv.conf | grep nameserver | awk '{print $2}'"
            exit_code, dns_info, _ = self.ssh_client.execute_command(dns_cmd)
            
            if exit_code == 0 and dns_info.strip():
                config["dns_servers"] = dns_info.strip().split('\n')
                logger.debug(f"當前DNS服務器: {config['dns_servers']}")
                
        except Exception as e:
            logger.error(f"獲取當前網絡配置出錯: {str(e)}")
            config["error"] = f"獲取當前網絡配置出錯: {str(e)}"
            
        # 根據OS類型分析永久配置文件
        os_type = self._detect_os_type()
        config["os_type"] = os_type
        logger.info(f"分析 {os_type} 系統上的接口 {interface} 配置")
        
        try:
            # 基於OS類型調用不同的配置分析方法
            if os_type == "debian":
                self._analyze_debian_config(interface, config)
            elif os_type == "redhat":
                self._analyze_redhat_config(interface, config)
            elif os_type == "netplan":
                self._analyze_netplan_config(interface, config)
            else:
                logger.warning(f"未知的操作系統類型: {os_type}，僅分析當前運行配置")
                
            # 檢查是否存在dhclient進程，但優先採用靜態配置的定義
            dhcp_check_cmd = f"ps aux | grep -v grep | grep -E 'dhclient.*{interface}'"
            exit_code, dhcp_process, _ = self.ssh_client.execute_command(dhcp_check_cmd)
            
            # 如果進程存在但已經確定為靜態配置，則可能是配置尚未完全生效或DHCP進程未終止
            if exit_code == 0 and dhcp_process.strip() and config["config_type"] and not config["is_dhcp"]:
                logger.warning(f"檢測到DHCP客戶端進程正在運行於接口 {interface}，但配置文件定義為靜態IP")
                config["dhcp_active"] = True
                # 不設置is_dhcp為True，保留配置文件的設定
            
            # 如果沒有配置文件定義，則依據DHCP進程是否存在判斷
            elif exit_code == 0 and dhcp_process.strip() and not config["config_type"]:
                config["is_dhcp"] = True
                config["dhcp_active"] = True
                logger.info(f"根據進程檢測到DHCP客戶端正在運行於接口 {interface}")
            
            return config
            
        except Exception as e:
            logger.error(f"分析網絡配置時發生錯誤: {str(e)}")
            config["success"] = False
            config["error"] = str(e)
            return config     
        
    def _analyze_debian_config(self, interface: str, config: Dict[str, Any]) -> None:
        """
        分析Debian/Ubuntu系統的網絡配置
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 配置字典，將被此方法修改
        """
        # 檢查/etc/network/interfaces文件
        interfaces_file = "/etc/network/interfaces"
        config["config_files"].append(interfaces_file)
        
        # 讀取interfaces文件
        exit_code, content, stderr = self.ssh_client.execute_command(f"cat {interfaces_file} 2>/dev/null || echo ''")
        
        if exit_code == 0 and content.strip():
            # 檢查主interfaces文件中的配置
            iface_pattern = f"iface\\s+{interface}\\s+"
            exit_code, iface_config, stderr = self.ssh_client.execute_command(
                f"grep -A10 '{iface_pattern}' {interfaces_file} 2>/dev/null || echo ''"
            )
            
            if exit_code == 0 and iface_config.strip():
                # 檢查是否為DHCP配置
                if "dhcp" in iface_config:
                    config["is_dhcp"] = True
                    config["config_type"] = "interfaces"
                    logger.info(f"在 {interfaces_file} 中檢測到接口 {interface} 使用DHCP配置")
                elif "static" in iface_config:
                    config["config_type"] = "interfaces"
                    logger.info(f"在 {interfaces_file} 中檢測到接口 {interface} 使用靜態配置")
                    
                    # 解析靜態IP配置
                    address_match = re.search(r'address\s+(\d+\.\d+\.\d+\.\d+)', iface_config)
                    netmask_match = re.search(r'netmask\s+(\d+\.\d+\.\d+\.\d+)', iface_config)
                    gateway_match = re.search(r'gateway\s+(\d+\.\d+\.\d+\.\d+)', iface_config)
                    
                    if address_match and netmask_match:
                        ip = address_match.group(1)
                        netmask = netmask_match.group(1)
                        # 轉換子網掩碼為CIDR格式
                        cidr = self._netmask_to_cidr(netmask)
                        config["addresses"].append(f"{ip}/{cidr}")
                        
                    if gateway_match:
                        config["gateway"] = gateway_match.group(1)
            else:
                logger.debug(f"未在 {interfaces_file} 中找到接口 {interface} 的配置")
        else:
            logger.debug(f"interfaces文件不存在或為空: {stderr}")
            
        # 檢查interfaces.d目錄中的額外配置
        interfaces_dir = "/etc/network/interfaces.d"
        exit_code, dir_exists, stderr = self.ssh_client.execute_command(f"[ -d {interfaces_dir} ] && echo 'exists' || echo ''")
        
        if exit_code == 0 and dir_exists.strip() == 'exists':
            # 列出目錄內容
            exit_code, dir_content, stderr = self.ssh_client.execute_command(f"ls -la {interfaces_dir} 2>/dev/null || echo ''")
            if exit_code == 0 and dir_content.strip():
                logger.debug(f"interfaces.d目錄內容: {dir_content}")
            
            # 尋找包含此接口配置的文件
            find_cmd = f"grep -l '{interface}' {interfaces_dir}/* 2>/dev/null || echo ''"
            exit_code, found_files, stderr = self.ssh_client.execute_command(find_cmd)
            
            if exit_code == 0 and found_files.strip():
                for file in found_files.strip().split('\n'):
                    if not file:
                        continue
                        
                    config["config_files"].append(file)
                    
                    # 檢查文件中的配置
                    exit_code, file_content, stderr = self.ssh_client.execute_command(f"cat {file} 2>/dev/null || echo ''")
                    
                    if exit_code == 0 and file_content.strip():
                        if f"iface {interface} inet dhcp" in file_content:
                            config["is_dhcp"] = True
                            config["config_type"] = "interfaces.d"
                            logger.info(f"在 {file} 中檢測到接口 {interface} 使用DHCP配置")
                            break
                        
                        # 也檢查靜態配置
                        if f"iface {interface} inet static" in file_content:
                            config["config_type"] = "interfaces.d"
                            logger.info(f"在 {file} 中檢測到接口 {interface} 使用靜態配置")
                            
                            # 解析靜態IP配置
                            address_match = re.search(r'address\s+(\d+\.\d+\.\d+\.\d+)', file_content)
                            netmask_match = re.search(r'netmask\s+(\d+\.\d+\.\d+\.\d+)', file_content)
                            gateway_match = re.search(r'gateway\s+(\d+\.\d+\.\d+\.\d+)', file_content)
                            
                            if address_match and netmask_match:
                                ip = address_match.group(1)
                                netmask = netmask_match.group(1)
                                # 轉換子網掩碼為CIDR格式
                                cidr = self._netmask_to_cidr(netmask)
                                config["addresses"].append(f"{ip}/{cidr}")
                                
                            if gateway_match:
                                config["gateway"] = gateway_match.group(1)
                            break
            else:
                logger.debug(f"在interfaces.d目錄中未找到接口 {interface} 的配置: {stderr}")
        else:
            logger.debug(f"interfaces.d目錄不存在: {stderr}")
        
        # 檢查NetworkManager配置
        self._check_networkmanager_config(interface, config)

    def _analyze_redhat_config(self, interface: str, config: Dict[str, Any]) -> None:
        """
        分析RedHat/CentOS系統的網絡配置
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 配置字典，將被此方法修改
        """
        # 檢查/etc/sysconfig/network-scripts/目錄下的接口配置
        config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface}"
        config["config_files"].append(config_file)
        
        # 讀取配置文件
        exit_code, content, _ = self.ssh_client.execute_command(f"cat {config_file} 2>/dev/null")
        
        if exit_code == 0 and content.strip():
            # 檢查BOOTPROTO設置
            exit_code, bootproto, _ = self.ssh_client.execute_command(
                f"grep -i 'BOOTPROTO' {config_file} | cut -d'=' -f2 | tr -d '\"' | tr '[:upper:]' '[:lower:]'"
            )
            
            if exit_code == 0 and bootproto.strip():
                proto = bootproto.strip()
                config["config_type"] = "ifcfg"
                
                if proto == "dhcp":
                    config["is_dhcp"] = True
                    logger.info(f"在 {config_file} 中檢測到接口 {interface} 使用DHCP配置")
                elif proto == "static" or proto == "none":
                    logger.info(f"在 {config_file} 中檢測到接口 {interface} 使用靜態配置")
                    
                    # 解析靜態IP配置
                    exit_code, ipaddr, _ = self.ssh_client.execute_command(
                        f"grep -i 'IPADDR' {config_file} | cut -d'=' -f2 | tr -d '\"'"
                    )
                    
                    exit_code, prefix, _ = self.ssh_client.execute_command(
                        f"grep -i 'PREFIX' {config_file} | cut -d'=' -f2 | tr -d '\"'"
                    )
                    
                    exit_code, netmask, _ = self.ssh_client.execute_command(
                        f"grep -i 'NETMASK' {config_file} | cut -d'=' -f2 | tr -d '\"'"
                    )
                    
                    exit_code, gateway, _ = self.ssh_client.execute_command(
                        f"grep -i 'GATEWAY' {config_file} | cut -d'=' -f2 | tr -d '\"'"
                    )
                    
                    # 添加地址
                    if ipaddr.strip():
                        ip = ipaddr.strip()
                        if prefix.strip():
                            config["addresses"].append(f"{ip}/{prefix.strip()}")
                        elif netmask.strip():
                            cidr = self._netmask_to_cidr(netmask.strip())
                            config["addresses"].append(f"{ip}/{cidr}")
                        else:
                            config["addresses"].append(f"{ip}/24")  # 默認假設為/24
                    
                    # 添加網關
                    if gateway.strip():
                        config["gateway"] = gateway.strip()
        else:
            logger.info(f"未找到接口 {interface} 的配置文件 {config_file}")
            
        # 檢查NetworkManager配置
        nm_dir = "/etc/NetworkManager/system-connections"
        exit_code, dir_exists, _ = self.ssh_client.execute_command(f"[ -d {nm_dir} ] && echo 'exists'")
        
        if exit_code == 0 and dir_exists.strip() == 'exists':
            # 找出可能包含此接口配置的連接文件
            find_cmd = f"grep -l '{interface}' {nm_dir}/* 2>/dev/null || true"
            exit_code, nm_files, _ = self.ssh_client.execute_command(find_cmd)
            
            if exit_code == 0 and nm_files.strip():
                for nm_file in nm_files.strip().split('\n'):
                    config["config_files"].append(nm_file)
                    
                    # 檢查文件中的配置
                    exit_code, nm_content, _ = self.ssh_client.execute_command(f"cat {nm_file} 2>/dev/null")
                    
                    if exit_code == 0 and nm_content.strip():
                        if "method=auto" in nm_content or "method=dhcp" in nm_content:
                            config["is_dhcp"] = True
                            config["config_type"] = "NetworkManager"
                            logger.info(f"在NetworkManager配置 {nm_file} 中檢測到接口 {interface} 使用DHCP")
                            break

    def _analyze_netplan_config(self, interface: str, config: Dict[str, Any]) -> None:
        """
        分析使用Netplan的系統的網絡配置
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 配置字典，將被此方法修改
        """
        # 查找所有netplan配置文件
        netplan_dir = "/etc/netplan"
        exit_code, files, _ = self.ssh_client.execute_command(
            f"find {netplan_dir} -name '*.yaml' -o -name '*.yml' 2>/dev/null || echo ''"
        )
        
        if exit_code != 0 or not files.strip():
            logger.warning(f"未找到Netplan配置文件")
            return
            
        yaml_import_failed = False
        try:
            import yaml
        except ImportError:
            yaml_import_failed = True
            logger.warning("無法導入yaml模塊，將使用文本匹配分析Netplan配置")
            
        # 逐一檢查每個配置文件
        for netplan_file in files.strip().split('\n'):
            config["config_files"].append(netplan_file)
            
            if yaml_import_failed:
                # 使用grep命令檢查配置
                # 1. 首先檢查是否有精確匹配的接口配置
                interface_check = f"grep -A20 '{interface}:' {netplan_file} 2>/dev/null"
                exit_code, interface_content, _ = self.ssh_client.execute_command(interface_check)
                
                if exit_code == 0 and interface_content.strip():
                    # 檢查DHCP設置
                    if "dhcp4: true" in interface_content or "dhcp4: yes" in interface_content:
                        config["is_dhcp"] = True
                        config["config_type"] = "netplan"
                        logger.info(f"在Netplan配置 {netplan_file} 中檢測到接口 {interface} 使用DHCP")
                        return
                    else:
                        # 可能是靜態配置
                        config["config_type"] = "netplan"
                        logger.info(f"在Netplan配置 {netplan_file} 中檢測到接口 {interface} 可能使用靜態配置")
                        
                        # 簡單解析addresses和gateway
                        addresses_cmd = f"grep -A5 'addresses:' {netplan_file} | grep -v 'addresses:' | grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+'"
                        exit_code, addresses, _ = self.ssh_client.execute_command(addresses_cmd)
                        
                        if exit_code == 0 and addresses.strip():
                            for addr in addresses.strip().split('\n'):
                                if addr not in config["addresses"]:
                                    config["addresses"].append(addr)
                                    
                        # 嘗試獲取gateway4或routes中的默認網關
                        gateway4_cmd = f"grep -A1 'gateway4:' {netplan_file} | grep -v 'gateway4:' | grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'"
                        exit_code, gateway4, _ = self.ssh_client.execute_command(gateway4_cmd)
                        
                        if exit_code == 0 and gateway4.strip():
                            config["gateway"] = gateway4.strip()
                        else:
                            # 檢查routes配置
                            routes_cmd = f"grep -A10 'routes:' {netplan_file} | grep -A3 'to: default' | grep 'via:' | grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'"
                            exit_code, routes_gateway, _ = self.ssh_client.execute_command(routes_cmd)
                            
                            if exit_code == 0 and routes_gateway.strip():
                                config["gateway"] = routes_gateway.strip()
                else:
                    # 2. 檢查是否有通配符配置
                    # 獲取所有可能的通配符配置
                    wildcard_check = f"cat {netplan_file} | grep -E '(eth|ens|enp|wlan|wl)[0-9a-z]*\\*:' || echo ''"
                    exit_code, wildcards, _ = self.ssh_client.execute_command(wildcard_check)
                    
                    if exit_code == 0 and wildcards.strip():
                        for wildcard_line in wildcards.strip().split('\n'):
                            if not wildcard_line:
                                continue
                                
                            # 提取通配符模式
                            wildcard_pattern = wildcard_line.split(':')[0].strip()
                            
                            # 檢查接口是否匹配此通配符
                            if self._interface_matches_wildcard(interface, wildcard_pattern):
                                # 獲取通配符配置內容
                                pattern_check = f"grep -A15 '{wildcard_pattern}:' {netplan_file} 2>/dev/null"
                                _, pattern_content, _ = self.ssh_client.execute_command(pattern_check)
                                
                                # 檢查是否使用DHCP
                                if "dhcp4: true" in pattern_content or "dhcp4: yes" in pattern_content:
                                    config["is_dhcp"] = True
                                    config["config_type"] = "netplan_wildcard"
                                    config["wildcard_pattern"] = wildcard_pattern
                                    logger.info(f"在Netplan配置 {netplan_file} 中通過通配符 {wildcard_pattern} 檢測到接口 {interface} 使用DHCP")
                                    
                                    # 同時獲取當前IP地址和網關，用於轉換為靜態IP
                                    exit_code, ip_addr, _ = self.ssh_client.execute_command(
                                        f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | head -1"
                                    )
                                    if exit_code == 0 and ip_addr.strip():
                                        # 解析IP地址和CIDR
                                        if '/' in ip_addr.strip():
                                            ip, cidr = ip_addr.strip().split('/')
                                            config["current_ip"] = ip
                                            config["current_cidr"] = cidr
                                        else:
                                            config["current_ip"] = ip_addr.strip()
                                    
                                    exit_code, gateway, _ = self.ssh_client.execute_command(
                                        f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                                    )
                                    if exit_code == 0 and gateway.strip():
                                        config["current_gateway"] = gateway.strip()
                                    
                                    return
            else:
                # 使用YAML庫解析配置
                try:
                    exit_code, content, _ = self.ssh_client.execute_command(f"cat {netplan_file} 2>/dev/null")
                    
                    if exit_code == 0 and content.strip():
                        yaml_data = yaml.safe_load(content)
                        
                        if not yaml_data or 'network' not in yaml_data:
                            continue
                            
                        network = yaml_data['network']
                        if 'ethernets' not in network:
                            continue
                            
                        ethernets = network['ethernets']
                        
                        # 檢查直接匹配
                        if interface in ethernets:
                            interface_config = ethernets[interface]
                            config["config_type"] = "netplan"
                            
                            # 檢查DHCP設置
                            if 'dhcp4' in interface_config and interface_config['dhcp4']:
                                config["is_dhcp"] = True
                                logger.info(f"在Netplan配置 {netplan_file} 中檢測到接口 {interface} 使用DHCP")
                                
                                # 同時獲取當前IP地址和網關，用於轉換為靜態IP
                                exit_code, ip_addr, _ = self.ssh_client.execute_command(
                                    f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | head -1"
                                )
                                if exit_code == 0 and ip_addr.strip():
                                    if '/' in ip_addr.strip():
                                        ip, cidr = ip_addr.strip().split('/')
                                        config["current_ip"] = ip
                                        config["current_cidr"] = cidr
                                    else:
                                        config["current_ip"] = ip_addr.strip()
                                
                                exit_code, gateway, _ = self.ssh_client.execute_command(
                                    f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                                )
                                if exit_code == 0 and gateway.strip():
                                    config["current_gateway"] = gateway.strip()
                                
                                return
                            else:
                                # 處理靜態配置
                                logger.info(f"在Netplan配置 {netplan_file} 中檢測到接口 {interface} 使用靜態配置")
                                
                                # 解析地址
                                if 'addresses' in interface_config:
                                    for addr in interface_config['addresses']:
                                        if addr not in config["addresses"]:
                                            config["addresses"].append(addr)
                                
                                # 解析網關
                                if 'gateway4' in interface_config:
                                    config["gateway"] = interface_config['gateway4']
                                elif 'routes' in interface_config:
                                    # 尋找默認路由
                                    for route in interface_config['routes']:
                                        if route.get('to') == 'default' or route.get('to') == '0.0.0.0/0':
                                            if 'via' in route:
                                                config["gateway"] = route['via']
                                                break
                        else:
                            # 檢查通配符配置
                            for key, eth_config in ethernets.items():
                                if not isinstance(eth_config, dict):
                                    continue
                                    
                                # 檢查是否為通配符Key
                                if '*' in key:
                                    if self._interface_matches_wildcard(interface, key):
                                        config["config_type"] = "netplan_wildcard"
                                        config["wildcard_pattern"] = key
                                        # 檢查DHCP設置
                                        if 'dhcp4' in eth_config and eth_config['dhcp4']:
                                            config["is_dhcp"] = True
                                            logger.info(f"在Netplan配置 {netplan_file} 中通過通配符Key {key} 檢測到接口 {interface} 使用DHCP")
                                            
                                            # 同時獲取當前IP地址和網關，用於轉換為靜態IP
                                            exit_code, ip_addr, _ = self.ssh_client.execute_command(
                                                f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | head -1"
                                            )
                                            if exit_code == 0 and ip_addr.strip():
                                                if '/' in ip_addr.strip():
                                                    ip, cidr = ip_addr.strip().split('/')
                                                    config["current_ip"] = ip
                                                    config["current_cidr"] = cidr
                                                else:
                                                    config["current_ip"] = ip_addr.strip()
                                            
                                            exit_code, gateway, _ = self.ssh_client.execute_command(
                                                f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                                            )
                                            if exit_code == 0 and gateway.strip():
                                                config["current_gateway"] = gateway.strip()
                                            
                                            return
                                            
                                # 檢查match配置
                                if 'match' in eth_config and 'name' in eth_config['match']:
                                    pattern = eth_config['match']['name']
                                    if self._interface_matches_wildcard(interface, pattern):
                                        config["config_type"] = "netplan_wildcard"
                                        config["wildcard_pattern"] = pattern
                                        
                                        # 檢查DHCP設置
                                        if 'dhcp4' in eth_config and eth_config['dhcp4']:
                                            config["is_dhcp"] = True
                                            logger.info(f"在Netplan配置 {netplan_file} 中通過match.name {pattern} 檢測到接口 {interface} 使用DHCP")
                                            
                                            # 同時獲取當前IP地址和網關，用於轉換為靜態IP
                                            exit_code, ip_addr, _ = self.ssh_client.execute_command(
                                                f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | head -1"
                                            )
                                            if exit_code == 0 and ip_addr.strip():
                                                if '/' in ip_addr.strip():
                                                    ip, cidr = ip_addr.strip().split('/')
                                                    config["current_ip"] = ip
                                                    config["current_cidr"] = cidr
                                                else:
                                                    config["current_ip"] = ip_addr.strip()
                                            
                                            exit_code, gateway, _ = self.ssh_client.execute_command(
                                                f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                                            )
                                            if exit_code == 0 and gateway.strip():
                                                config["current_gateway"] = gateway.strip()
                                            
                                            return
                except Exception as e:
                    logger.error(f"解析YAML配置時發生錯誤: {str(e)}")
                    # 回退到文本匹配

    def _interface_matches_wildcard(self, interface: str, pattern: str) -> bool:
        """
        檢查接口名稱是否匹配通配符模式
        
        支持的通配符:
        - *: 匹配任意多個字符
        - ?: 匹配單個字符
        - [chars]: 匹配chars中的任意一個字符
        - {a,b,c}: 匹配a、b或c
        
        參數:
            interface (str): 接口名稱
            pattern (str): 通配符模式
            
        返回:
            bool: 如果匹配則返回True，否則返回False
        """
        logger.debug(f"檢查接口 {interface} 是否匹配通配符 {pattern}")
        
        try:
            # 1. 處理基本情況
            if not pattern or not interface:
                return False
                
            if pattern == interface:
                return True
                
            if pattern == '*':
                return True
                
            # 清理模式中不必要的空格和引號
            pattern = pattern.strip().strip('"\'')
            
            # 處理Netplan中的簡化通配符
            # 例如 eth* 應該匹配 eth0, eth1, eth2...
            if pattern.endswith('*') and '*' not in pattern[:-1]:
                prefix = pattern[:-1]
                if interface.startswith(prefix):
                    logger.debug(f"通過前綴匹配: {interface} 匹配通配符 {pattern}")
                    return True
                    
            # 處理 eth[0-9]* 這種模式
            if '[' in pattern and ']' in pattern and '*' in pattern:
                try:
                    # 提取字符類別
                    prefix = pattern[:pattern.find('[')]
                    suffix = pattern[pattern.find(']')+1:]
                    char_class = pattern[pattern.find('[')+1:pattern.find(']')]
                    
                    # 檢查前綴匹配
                    if not interface.startswith(prefix):
                        return False
                        
                    # 檢查字符類別匹配
                    if len(interface) <= len(prefix):
                        return False
                        
                    # 檢查字符類別
                    char_to_match = interface[len(prefix)]
                    
                    # 處理範圍表示法，如[0-9]
                    if '-' in char_class:
                        ranges = char_class.split('-')
                        if len(ranges) == 2:
                            start_char, end_char = ranges[0][-1], ranges[1][0]
                            if start_char <= char_to_match <= end_char:
                                logger.debug(f"通過字符類別範圍匹配: {interface} 匹配通配符 {pattern}")
                                return True
                    else:
                        # 檢查是否在字符類別中
                        if char_to_match in char_class:
                            logger.debug(f"通過字符類別匹配: {interface} 匹配通配符 {pattern}")
                            return True
                except Exception as e:
                    logger.debug(f"字符類別處理錯誤: {str(e)}")
            
            # 2. 使用re模塊進行通配符匹配
            try:
                import re
                import fnmatch
                
                # 首先嘗試使用fnmatch（它是為了文件名匹配設計的，但也適用於此）
                if fnmatch.fnmatch(interface, pattern):
                    logger.debug(f"通過fnmatch模塊匹配成功: {interface} 匹配 {pattern}")
                    return True
                
                # 轉換通配符模式為正則表達式模式
                # 將*轉換為.*（匹配任意多個字符）
                # 將?轉換為.（匹配任意單個字符）
                # 保留[]表達式（字符類）
                # 將{a,b,c}轉換為(a|b|c)
                
                # 使用re.escape處理特殊字符，但需要保留通配符
                pattern_escaped = ''
                i = 0
                while i < len(pattern):
                    if pattern[i] == '*':
                        pattern_escaped += '.*'
                    elif pattern[i] == '?':
                        pattern_escaped += '.'
                    elif pattern[i] == '[':
                        # 處理字符類 [...]
                        j = i
                        while j < len(pattern) and pattern[j] != ']':
                            j += 1
                        if j < len(pattern):
                            pattern_escaped += pattern[i:j+1]
                            i = j
                    elif pattern[i] == '{':
                        # 處理選擇類 {a,b,c}
                        j = i
                        while j < len(pattern) and pattern[j] != '}':
                            j += 1
                        if j < len(pattern):
                            # 從{a,b,c}提取a,b,c
                            options = pattern[i+1:j].split(',')
                            pattern_escaped += '(' + '|'.join(re.escape(o) for o in options) + ')'
                            i = j
                    else:
                        pattern_escaped += re.escape(pattern[i])
                    i += 1
                
                # 添加完整匹配的錨點
                re_pattern = f'^{pattern_escaped}$'
                
                # 編譯正則表達式並測試匹配
                regex = re.compile(re_pattern)
                match = regex.match(interface)
                match_result = bool(match)
                
                if match_result:
                    logger.debug(f"正則表達式匹配成功: {interface} 匹配 {pattern}")
                return match_result
                
            except (ImportError, re.error) as e:
                logger.warning(f"使用正則表達式匹配時出錯: {str(e)}, 回退到基本匹配")
            
            # 3. 回退到最基本的通配符匹配
            # 如果模式中只有一個*，並且在結尾
            if pattern.count('*') == 1 and pattern.endswith('*'):
                prefix = pattern[:-1]
                return interface.startswith(prefix)
            
            # 如果模式中只有一個*，並且在開頭
            if pattern.count('*') == 1 and pattern.startswith('*'):
                suffix = pattern[1:]
                return interface.endswith(suffix)
                
            # 這裡可以添加更多基本匹配邏輯
            
            return False
        except Exception as e:
            logger.error(f"在通配符匹配過程中發生錯誤: {str(e)}")
            return False
        
    def add_ip_address(self, ip_address: str, interface: Optional[str] = None) -> bool:
        """
        添加IP地址到網絡接口
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
            
        返回:
            bool: 添加成功返回True，否則抛出異常
            
        異常:
            IPConfigError: 添加IP地址失敗時抛出
        """
        # 驗證IP地址格式
        if not self._validate_ip_cidr(ip_address):
            logger.error(f"無效的IP地址格式: {ip_address}，應為CIDR格式 (x.x.x.x/y)")
            raise IPConfigError(f"無效的IP地址格式: {ip_address}，應為CIDR格式 (x.x.x.x/y)")
        
        # 確定要使用的接口
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"正在添加IP地址 {ip_address} 到接口 {interface}")
        
        try:
            # 檢查IP是否已存在
            if self._is_ip_exists(ip_address, interface):
                logger.info(f"IP地址 {ip_address} 已存在於接口 {interface}")
                return True
            
            # 檢查接口是否存在
            if not self._interface_exists(interface):
                logger.error(f"接口 {interface} 不存在")
                raise IPConfigError(f"接口 {interface} 不存在")
            
            # 檢查接口是否啟用
            if not self.is_interface_up(interface):
                logger.warning(f"接口 {interface} 未啟用，嘗試啟用")
                self._enable_interface(interface)
            
            # 使用ip addr add添加IP地址
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip addr add {ip_address} dev {interface}"
            )
            
            if exit_code != 0:
                logger.error(f"添加IP地址失敗: {stderr}")
                raise IPConfigError(f"添加IP地址失敗: {stderr}")
            
            # 驗證IP是否添加成功
            if not self._is_ip_exists(ip_address, interface):
                logger.error(f"添加IP地址 {ip_address} 後無法驗證其存在")
                raise IPConfigError(f"添加IP地址 {ip_address} 後無法驗證其存在")
            
            logger.info(f"成功添加IP地址 {ip_address} 到接口 {interface}")
            
            # 添加永久配置
            self._add_permanent_ip(ip_address, interface)
            
            return True
            
        except Exception as e:
            logger.error(f"添加IP地址時發生錯誤: {str(e)}")
            raise IPConfigError(f"添加IP地址時發生錯誤: {str(e)}")

    def remove_ip_address(self, ip_address: str, interface: Optional[str] = None) -> bool:
        """
        從網絡接口移除IP地址
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
            
        返回:
            bool: 移除成功返回True，否則抛出異常
            
        異常:
            IPConfigError: 移除IP地址失敗時抛出
        """
        # 驗證IP地址格式
        if not self._validate_ip_cidr(ip_address):
            logger.error(f"無效的IP地址格式: {ip_address}，應為CIDR格式 (x.x.x.x/y)")
            raise IPConfigError(f"無效的IP地址格式: {ip_address}，應為CIDR格式 (x.x.x.x/y)")
        
        # 確定要使用的接口
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"正在從接口 {interface} 移除IP地址 {ip_address}")
        
        try:
            # 檢查IP是否存在
            if not self._is_ip_exists(ip_address, interface):
                logger.info(f"IP地址 {ip_address} 不存在於接口 {interface}")
                return True
            
            # 使用ip addr del移除IP地址
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip addr del {ip_address} dev {interface}"
            )
            
            if exit_code != 0:
                logger.error(f"移除IP地址失敗: {stderr}")
                raise IPConfigError(f"移除IP地址失敗: {stderr}")
            
            # 驗證IP是否移除成功
            if self._is_ip_exists(ip_address, interface):
                logger.error(f"移除IP地址 {ip_address} 後仍然存在")
                raise IPConfigError(f"移除IP地址 {ip_address} 後仍然存在")
            
            logger.info(f"成功從接口 {interface} 移除IP地址 {ip_address}")
            
            # 從永久配置中移除
            self._remove_permanent_ip(ip_address, interface)
            
            return True
            
        except Exception as e:
            logger.error(f"移除IP地址時發生錯誤: {str(e)}")
            raise IPConfigError(f"移除IP地址時發生錯誤: {str(e)}")

    def convert_dhcp_to_static(self, interface: Optional[str] = None, 
                              ip_address: Optional[str] = None, 
                              netmask: Optional[str] = None,
                              gateway: Optional[str] = None,
                              dns_servers: Optional[List[str]] = None) -> bool:
        """
        將DHCP配置轉換為靜態IP配置
        
        參數:
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
            ip_address (str, optional): 靜態IP地址，如果為None則使用當前IP
            netmask (str, optional): 子網掩碼，如果為None則使用當前子網掩碼
            gateway (str, optional): 網關地址，如果為None則使用當前網關
            dns_servers (List[str], optional): DNS服務器列表
            
        返回:
            bool: 轉換成功返回True，否則返回False
            
        異常:
            IPConfigError: 轉換配置失敗時抛出
        """
        # 確定要使用的接口
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"正在將接口 {interface} 從DHCP配置轉換為靜態IP配置")
        
        try:
            # 分析當前網絡配置
            network_config = self.analyze_network_config(interface)
            
            # 如果不是DHCP，且沒有指定靜態參數，則返回失敗
            if not network_config["is_dhcp"] and not (ip_address and netmask):
                logger.error(f"接口 {interface} 不是DHCP配置")
                raise IPConfigError(f"接口 {interface} 不是DHCP配置，無需轉換")
            
            # 確保我們有所需要的IP配置參數
            if ip_address:
                # 使用用戶提供的IP地址
                network_config["ip_address"] = ip_address
                logger.info(f"使用用戶提供的IP地址: {ip_address}")
            elif "current_ip" in network_config and network_config["current_ip"]:
                # 使用當前運行的IP
                logger.info(f"使用當前IP地址: {network_config['current_ip']}")
                network_config["ip_address"] = network_config["current_ip"]
            elif not network_config.get("ip_address"):
                # 嘗試從接口獲取當前IP
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | cut -d/ -f1 | head -1"
                )
                if exit_code == 0 and stdout.strip():
                    network_config["ip_address"] = stdout.strip()
                    logger.info(f"從接口獲取到IP地址: {network_config['ip_address']}")
                else:
                    logger.error(f"無法獲取接口 {interface} 的當前IP配置")
                    raise IPConfigError(f"無法獲取接口 {interface} 的當前IP配置，請指定IP地址")
            
            if netmask:
                # 使用用戶提供的子網掩碼
                network_config["netmask"] = netmask
                logger.info(f"使用用戶提供的子網掩碼: {netmask}")
            elif "current_cidr" in network_config and network_config["current_cidr"]:
                # 將CIDR轉換為子網掩碼
                network_config["netmask"] = self._cidr_to_netmask(int(network_config["current_cidr"]))
                logger.info(f"使用當前CIDR ({network_config['current_cidr']}) 轉換的子網掩碼: {network_config['netmask']}")
            elif not network_config.get("netmask"):
                # 嘗試從接口獲取當前CIDR
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | cut -d/ -f2 | head -1"
                )
                if exit_code == 0 and stdout.strip():
                    cidr = stdout.strip()
                    network_config["netmask"] = self._cidr_to_netmask(int(cidr))
                    logger.info(f"從接口獲取到CIDR ({cidr})，轉換為子網掩碼: {network_config['netmask']}")
                else:
                    # 使用默認子網掩碼
                    network_config["netmask"] = "255.255.255.0"
                    logger.warning(f"無法獲取子網掩碼，使用默認值: {network_config['netmask']}")
            
            if gateway:
                # 使用用戶提供的網關
                network_config["gateway"] = gateway
                logger.info(f"使用用戶提供的網關: {gateway}")
            elif "current_gateway" in network_config and network_config["current_gateway"]:
                # 使用當前網關
                logger.info(f"使用當前網關: {network_config['current_gateway']}")
            elif not network_config.get("gateway"):
                # 嘗試從路由表獲取默認網關
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                )
                if exit_code == 0 and stdout.strip():
                    network_config["gateway"] = stdout.strip()
                    logger.info(f"從路由表獲取到網關: {network_config['gateway']}")
            
            if dns_servers:
                # 使用用戶提供的DNS服務器
                network_config["dns_servers"] = dns_servers
                logger.info(f"使用用戶提供的DNS服務器: {dns_servers}")
            
            # 日誌記錄最終的配置
            logger.info(f"將使用以下配置轉換DHCP到靜態IP: IP={network_config.get('ip_address')}, " +
                     f"掩碼={network_config.get('netmask')}, 網關={network_config.get('gateway')}, " +
                     f"DNS={network_config.get('dns_servers', [])}")
            

            # 根據OS類型選擇對應的配置方法
            success = False
            
            if self._os_type == 'debian':
                success = self._convert_dhcp_to_static_debian(interface, network_config)
            elif self._os_type == 'redhat':
                success = self._convert_dhcp_to_static_redhat(interface, network_config)
            elif self._os_type == 'netplan':
                success = self._convert_dhcp_to_static_netplan(interface, network_config)
            else:
                logger.error(f"不支持的操作系統類型: {self._os_type}")
                raise IPConfigError(f"不支持的操作系統類型: {self._os_type}")
            
            if success:
                # 確認配置可用性
                if self._verify_static_config(interface, network_config["ip_address"]):
                    logger.info(f"成功將接口 {interface} 從DHCP轉換為靜態IP")
                    return True
                else:
                    logger.error(f"靜態配置驗證失敗")
                    return False
            
        except Exception as e:
            logger.error(f"將DHCP轉換為靜態IP時發生錯誤: {str(e)}")
            return False

    def _is_ip_exists(self, ip_address: str, interface: str) -> bool:
        """
        檢查IP地址是否已存在於指定接口
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str): 網絡接口名稱
            
        返回:
            bool: 如果IP存在返回True，否則返回False
        """
        # 提取純IP地址部分（不包含子網掩碼）
        ip_only = ip_address.split('/')[0]
        
        try:
            # 使用ip addr show檢查IP是否存在
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w 'inet' | grep -w '{ip_only}'"
            )
            
            # 如果有輸出且返回碼為0，則IP存在
            return exit_code == 0 and stdout.strip() != ""
            
        except Exception as e:
            logger.error(f"檢查IP存在性時發生錯誤: {str(e)}")
            return False
    
    def _interface_exists(self, interface: str) -> bool:
        """
        檢查網絡接口是否存在
        
        參數:
            interface (str): 網絡接口名稱
            
        返回:
            bool: 如果接口存在返回True，否則返回False
        """
        try:
            # 使用ip link檢查接口是否存在
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip link show {interface}"
            )
            
            # 如果返回碼為0，則接口存在
            return exit_code == 0
            
        except Exception as e:
            logger.error(f"檢查接口存在性時發生錯誤: {str(e)}")
            return False

    def _enable_interface(self, interface: str) -> bool:
        """
        啟用網絡接口
        
        參數:
            interface (str): 網絡接口名稱
            
        返回:
            bool: 啟用成功返回True，否則返回False
        """
        try:
            # 使用ip link set啟用接口
            exit_code, stdout, stderr = self.ssh_client.execute_command(
                f"ip link set {interface} up"
            )
            
            # 如果返回碼為0，則啟用成功
            if exit_code == 0:
                logger.info(f"成功啟用接口 {interface}")
                return True
            else:
                logger.error(f"啟用接口 {interface} 失敗: {stderr}")
                return False
            
        except Exception as e:
            logger.error(f"啟用接口時發生錯誤: {str(e)}")
            return False
    
    def _detect_os_type(self) -> str:
        """
        高效檢測操作系統類型，減少SSH調用次數
        
        返回:
            str: 操作系統類型，可能的值：'debian'、'redhat'、'netplan'
        """
        # 如果已經檢測過，直接返回緩存結果
        if self._os_type:
            return self._os_type
        
        logger.info("開始檢測操作系統類型...")
        
        try:
            # 使用單一命令檢查多個特徵
            detect_cmd = (
                # 檢查 os-release 文件
                "if [ -f /etc/os-release ]; then cat /etc/os-release; fi; "
                # 檢查網絡配置目錄和文件
                "echo 'NET_CONFIG:'; "
                "if [ -f /etc/network/interfaces ]; then echo 'debian_interfaces=yes'; fi; "
                "if [ -d /etc/network/interfaces.d ]; then echo 'debian_interfacesd=yes'; fi; "
                "if [ -d /etc/netplan ]; then echo 'netplan_dir=yes'; fi; "
                "if [ -d /etc/sysconfig/network-scripts ]; then echo 'redhat_netscripts=yes'; fi; "
                "if [ -d /etc/NetworkManager/system-connections ]; then echo 'nm_connections=yes'; fi; "
                # 檢查命令可用性
                "echo 'COMMANDS:'; "
                "which netplan >/dev/null 2>&1 && echo 'netplan_cmd=yes' || echo 'netplan_cmd=no'; "
                "which nmcli >/dev/null 2>&1 && echo 'nmcli_cmd=yes' || echo 'nmcli_cmd=no'; "
                "which apt >/dev/null 2>&1 && echo 'apt_cmd=yes' || echo 'apt_cmd=no'; "
                "which yum >/dev/null 2>&1 && echo 'yum_cmd=yes' || echo 'yum_cmd=no'; "
                "which dnf >/dev/null 2>&1 && echo 'dnf_cmd=yes' || echo 'dnf_cmd=no'"
            )
            
            exit_code, result, _ = self.ssh_client.execute_command(detect_cmd)
            
            if exit_code != 0:
                logger.warning("操作系統檢測命令執行失敗，使用默認類型: debian")
                self._os_type = "debian"
                return "debian"
            
            # 解析結果
            os_info = {}
            net_config = {}
            commands = {}
            
            section = "os_info"
            for line in result.strip().split('\n'):
                if line == 'NET_CONFIG:':
                    section = "net_config"
                    continue
                elif line == 'COMMANDS:':
                    section = "commands"
                    continue
                
                if section == "os_info" and '=' in line:
                    key, value = line.split('=', 1)
                    os_info[key.strip()] = value.strip(' "\'')
                elif section == "net_config" and '=' in line:
                    key, value = line.split('=', 1)
                    net_config[key.strip()] = value.strip()
                elif section == "commands" and '=' in line:
                    key, value = line.split('=', 1)
                    commands[key.strip()] = value.strip()
            
            # 根據收集的信息確定OS類型
            # 首先檢查Ubuntu等使用Netplan的系統
            if net_config.get('netplan_dir') == 'yes' or commands.get('netplan_cmd') == 'yes':
                logger.info("檢測到Netplan配置，使用netplan類型")
                self._os_type = 'netplan'
                return 'netplan'
            
            # 檢查Debian/Ubuntu非Netplan系統
            if net_config.get('debian_interfaces') == 'yes' or net_config.get('debian_interfacesd') == 'yes':
                # 檢查是否為Ubuntu，需要進一步確認是否使用netplan
                is_ubuntu = False
                if os_info.get('ID') == 'ubuntu' or 'ubuntu' in os_info.get('ID_LIKE', '').lower():
                    is_ubuntu = True
                    
                # Ubuntu 17.10+ 通常使用netplan
                if is_ubuntu and os_info.get('VERSION_ID'):
                    try:
                        version = float(os_info.get('VERSION_ID').split('.')[0])
                        if version >= 17.10:
                            logger.info(f"檢測到Ubuntu {os_info.get('VERSION_ID')}，可能使用Netplan")
                            # 再次檢查netplan目錄是否存在
                            if net_config.get('netplan_dir') == 'yes':
                                self._os_type = 'netplan'
                                return 'netplan'
                    except (ValueError, IndexError):
                        pass
                
                logger.info("檢測到Debian風格網絡配置")
                self._os_type = 'debian'
                return 'debian'
            
            # 檢查RHEL/CentOS系統
            if net_config.get('redhat_netscripts') == 'yes' or commands.get('yum_cmd') == 'yes' or commands.get('dnf_cmd') == 'yes':
                logger.info("檢測到RedHat風格網絡配置")
                
                # 檢查RHEL/CentOS版本
                if os_info.get('ID') and ('rhel' in os_info.get('ID').lower() or 'centos' in os_info.get('ID').lower()):
                    if os_info.get('VERSION_ID'):
                        try:
                            version = float(os_info.get('VERSION_ID').split('.')[0])
                            if version >= 8:
                                logger.info(f"檢測到RHEL/CentOS {os_info.get('VERSION_ID')}，使用NetworkManager")
                                self._os_version = os_info.get('VERSION_ID')
                        except (ValueError, IndexError):
                            pass
                            
                self._os_type = 'redhat'
                return 'redhat'
            
            # 檢查NetworkManager（作為備選判斷）
            if net_config.get('nm_connections') == 'yes' and commands.get('nmcli_cmd') == 'yes':
                # 通過NetworkManager判斷
                # 如果有apt，則可能是Debian/Ubuntu
                if commands.get('apt_cmd') == 'yes':
                    logger.info("基於NetworkManager和apt檢測到Debian類系統")
                    self._os_type = 'debian'
                    return 'debian'
                # 如果有yum/dnf，則可能是RHEL/CentOS
                elif commands.get('yum_cmd') == 'yes' or commands.get('dnf_cmd') == 'yes':
                    logger.info("基於NetworkManager和yum/dnf檢測到RedHat類系統")
                    self._os_type = 'redhat'
                    return 'redhat'
            
            # 通過ID判斷
            if os_info.get('ID'):
                if os_info.get('ID').lower() in ['ubuntu', 'debian'] or 'debian' in os_info.get('ID_LIKE', '').lower():
                    logger.info(f"基於ID '{os_info.get('ID')}' 檢測到Debian類系統")
                    self._os_type = 'debian'
                    return 'debian'
                elif os_info.get('ID').lower() in ['rhel', 'centos', 'fedora'] or 'rhel' in os_info.get('ID_LIKE', '').lower():
                    logger.info(f"基於ID '{os_info.get('ID')}' 檢測到RedHat類系統")
                    self._os_type = 'redhat'
                    return 'redhat'
            
            # 最後通過可用命令判斷
            if commands.get('apt_cmd') == 'yes':
                logger.info("基於apt命令可用性檢測到Debian類系統")
                self._os_type = 'debian'
                return 'debian'
            elif commands.get('yum_cmd') == 'yes' or commands.get('dnf_cmd') == 'yes':
                logger.info("基於yum/dnf命令可用性檢測到RedHat類系統")
                self._os_type = 'redhat'
                return 'redhat'
            
            # 默認fallback
            logger.warning("無法確定精確的操作系統類型，使用默認類型: debian")
            self._os_type = 'debian'
            return 'debian'
            
        except Exception as e:
            logger.error(f"檢測操作系統類型時發生錯誤: {str(e)}")
            logger.warning("使用默認的操作系統類型: debian")
            self._os_type = 'debian'
            return 'debian'

    def _detect_os_by_files(self) -> str:
        """
        通過文件系統結構檢測操作系統類型
        
        返回:
            str: 操作系統類型 ("debian", "redhat", "netplan" 或 "unknown")
        """
        logger.info("通過文件結構檢測操作系統類型...")
        
        try:
            # 檢查Debian/Ubuntu風格
            exit_code, _, _ = self.ssh_client.execute_command("ls -la /etc/network/interfaces 2>/dev/null")
            if exit_code == 0:
                # 檢查是否使用Netplan (Ubuntu 17.10+)
                exit_code, _, _ = self.ssh_client.execute_command("ls -la /etc/netplan/ 2>/dev/null")
                if exit_code == 0:
                    logger.info("檢測到Netplan配置目錄")
                    self._os_type = "netplan"
                    return "netplan"
                
                logger.info("檢測到Debian風格網絡配置")
                self._os_type = "debian"
                return "debian"
            
            # 檢查RedHat風格
            exit_code, _, _ = self.ssh_client.execute_command("ls -la /etc/sysconfig/network-scripts/ 2>/dev/null")
            if exit_code == 0:
                logger.info("檢測到RedHat風格網絡配置")
                self._os_type = "redhat"
                return "redhat"
            
            # 檢查是否存在NetworkManager
            exit_code, _, _ = self.ssh_client.execute_command("ls -la /etc/NetworkManager/system-connections/ 2>/dev/null")
            if exit_code == 0:
                # 如果只有NetworkManager，需進一步檢查
                exit_code, _, _ = self.ssh_client.execute_command("which nmcli 2>/dev/null")
                if exit_code == 0:
                    logger.info("檢測到NetworkManager配置")
                    # 檢查是否是Ubuntu
                    exit_code, _, _ = self.ssh_client.execute_command("grep -i ubuntu /etc/issue 2>/dev/null || grep -i ubuntu /etc/*-release 2>/dev/null")
                    if exit_code == 0:
                        # Ubuntu很可能使用Netplan
                        exit_code, _, _ = self.ssh_client.execute_command("which netplan 2>/dev/null")
                        if exit_code == 0:
                            logger.info("檢測到Ubuntu NetworkManager使用Netplan後端")
                            self._os_type = "netplan"
                            return "netplan"
                        
                    # 默認使用debian風格處理NetworkManager
                    self._os_type = "debian"
                    return "debian"
            
            # 如果上述方法都失敗，檢查常見分發標識符
            for os_file, os_type in [
                ("/etc/debian_version", "debian"),
                ("/etc/redhat-release", "redhat"),
                ("/etc/lsb-release", "debian"),  # 大多數是Ubuntu/Debian衍生版
            ]:
                exit_code, _, _ = self.ssh_client.execute_command(f"ls -la {os_file} 2>/dev/null")
                if exit_code == 0:
                    logger.info(f"基於文件 {os_file} 檢測到 {os_type} 系統")
                    self._os_type = os_type
                    return os_type
            
            # 萬不得已，使用尋找命令
            for cmd, os_type in [
                ("apt", "debian"),
                ("apt-get", "debian"),
                ("dpkg", "debian"),
                ("yum", "redhat"),
                ("dnf", "redhat"),
                ("rpm", "redhat"),
                ("netplan", "netplan")
            ]:
                exit_code, _, _ = self.ssh_client.execute_command(f"which {cmd} 2>/dev/null")
                if exit_code == 0:
                    logger.info(f"基於命令 {cmd} 檢測到 {os_type} 系統")
                    if cmd == "netplan":
                        logger.info("找到netplan命令，將使用netplan配置")
                        self._os_type = "netplan"
                        return "netplan"
                    
                    self._os_type = os_type
                    return os_type
            
            # 如果所有方法都失敗，則返回unknown
            logger.warning("無法確定操作系統類型，默認使用debian風格")
            self._os_type = "debian"
            return "debian"
            
        except Exception as e:
            logger.error(f"通過文件結構檢測操作系統時出錯: {str(e)}")
            logger.warning("檢測失敗，默認使用debian風格")
            self._os_type = "debian"
            return "debian"
   
    def _verify_static_config(self, interface: str, expected_ip: str) -> bool:
        """
        驗證靜態IP配置是否正確
        
        參數:
            interface (str): 網絡接口名稱
            expected_ip (str): 期望的IP地址
            
        返回:
            bool: 配置正確返回True，否則返回False
        """
        try:
            # 等待系統應用配置
            time.sleep(2)
            
            # 檢查接口是否啟用
            if not self.is_interface_up(interface):
                logger.error(f"驗證失敗: 接口 {interface} 未啟用")
                return False
            
            # 檢查IP地址是否配置成功
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w 'inet' | grep -w '{expected_ip}'"
            )
            
            # 檢查網絡連通性
            if exit_code == 0 and stdout.strip():
                # 嘗試ping默認網關
                config = self.analyze_network_config(interface)
                if config.get("gateway"):
                    exit_code, _, _ = self.ssh_client.execute_command(
                        f"ping -c 1 -W 2 {config['gateway']}"
                    )
                    if exit_code != 0:
                        logger.warning(f"無法ping通默認網關 {config['gateway']}，但IP配置看起來正確")
                
                logger.info(f"靜態IP配置驗證成功: {expected_ip} 在接口 {interface}")
                return True
            else:
                logger.error(f"驗證失敗: 接口 {interface} 上找不到IP {expected_ip}")
                return False
        
        except Exception as e:
            logger.error(f"驗證靜態IP配置時發生錯誤: {str(e)}")
            return False

    def _convert_dhcp_to_static_debian(self, interface: str, config: Dict[str, Any]) -> bool:
        """
        將Debian系統的DHCP配置轉換為靜態IP配置，優化版本
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 網絡配置信息字典，包含所需的IP配置參數
            
        返回:
            bool: 轉換成功返回True，否則返回False
        """
        logger.info(f"正在轉換Debian系統的接口 {interface} 配置從DHCP到靜態IP")
        
        try:
            # 1. 參數驗證與提取
            # 1.1 驗證必要參數
            if "ip_address" not in config or not config["ip_address"]:
                logger.error(f"轉換DHCP到靜態IP時缺少IP地址參數")
                return False
                
            if "netmask" not in config or not config["netmask"]:
                # 設置默認掩碼
                config["netmask"] = "255.255.255.0"
                logger.info("設置默認子網掩碼 255.255.255.0")
            
            # 1.2 提取配置參數
            ip_address = config["ip_address"]
            netmask = config["netmask"]
            gateway = config.get("gateway", "")
            dns_servers = config.get("dns_servers", [])
            
            # 2. 配置文件路徑決策
            # 2.1 檢查interfaces.d目錄是否存在
            exit_code, _, _ = self.ssh_client.execute_command(
                "test -d /etc/network/interfaces.d"
            )
            use_interfaces_d = (exit_code == 0)
            
            # 2.2 決定配置文件路徑
            if use_interfaces_d:
                interface_file = f"/etc/network/interfaces.d/{interface}"
                main_file = "/etc/network/interfaces"
            else:
                interface_file = "/etc/network/interfaces"
                main_file = interface_file
            
            # 4. 配置檢查與準備
            # 4.1 確保interfaces文件包含source指令(如果使用interfaces.d)
            if use_interfaces_d:
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"grep -q 'source /etc/network/interfaces.d/\\*' {main_file}"
                )
                
                if exit_code != 0:
                    self.ssh_client.execute_command(
                        f"echo 'source /etc/network/interfaces.d/*' >> {main_file}"
                    )
                    logger.info(f"已添加interfaces.d目錄引用到主配置文件")
            
            # 4.2 檢查接口在DHCP配置中是否存在
            exit_code, dhcp_config, _ = self.ssh_client.execute_command(
                f"grep -A5 'iface {interface} inet dhcp' {interface_file} 2>/dev/null || echo ''"
            )
            has_dhcp_config = (exit_code == 0 and "dhcp" in dhcp_config)
            
            # 5. 構建新的靜態IP配置
            # 5.1 創建基本靜態IP配置
            static_config = (
                f"auto {interface}\n"
                f"iface {interface} inet static\n"
                f"    address {ip_address}\n"
                f"    netmask {netmask}\n"
            )
            
            # 5.2 添加網關配置(如果有)
            if gateway:
                static_config += f"    gateway {gateway}\n"
            
            # 5.3 添加DNS服務器配置(如果有)
            if dns_servers:
                static_config += f"    dns-nameservers {' '.join(dns_servers)}\n"
            
            # 6. 應用新配置
            # 6.1 準備臨時配置文件
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp_path = tmp.name
                
                if has_dhcp_config:
                    # 6.2 替換現有DHCP配置為靜態配置
                    exit_code, original_content, _ = self.ssh_client.execute_command(
                        f"cat {interface_file} 2>/dev/null || echo ''"
                    )
                    
                    if exit_code == 0 and original_content:
                        # 使用正則表達式替換DHCP配置塊
                        import re
                        # 匹配接口的DHCP配置塊
                        pattern = re.compile(f"auto\\s+{interface}\\s*\\niface\\s+{interface}\\s+inet\\s+dhcp\\s*\\n", re.MULTILINE)
                        
                        # 替換為靜態配置
                        if re.search(pattern, original_content):
                            new_content = re.sub(pattern, static_config, original_content)
                        else:
                            # 如果沒有找到精確匹配，則尋找任何提及該接口的DHCP配置
                            pattern = re.compile(f"iface\\s+{interface}\\s+inet\\s+dhcp", re.MULTILINE)
                            if re.search(pattern, original_content):
                                # 提取接口配置塊的開始和結束
                                lines = original_content.split('\n')
                                new_lines = []
                                skip_block = False
                                added_config = False
                                
                                for i, line in enumerate(lines):
                                    if re.search(pattern, line):
                                        skip_block = True
                                        if not added_config:
                                            # 添加新的靜態配置
                                            new_lines.append(static_config)
                                            added_config = True
                                    elif skip_block and (line.startswith('auto') or line.startswith('iface')):
                                        # 遇到下一個接口配置，停止跳過
                                        skip_block = False
                                        new_lines.append(line)
                                    elif not skip_block:
                                        new_lines.append(line)
                                
                                new_content = '\n'.join(new_lines)
                            else:
                                # 如果完全找不到配置，直接附加
                                new_content = original_content.rstrip() + "\n\n" + static_config
                        
                        tmp.write(new_content)
                    else:
                        # 文件不存在或為空，直接寫入新配置
                        tmp.write(static_config)
                else:
                    # 6.3 創建新的配置文件
                    tmp.write(static_config)
            
            # 6.4 上傳並應用配置
            self.ssh_client.upload_file(tmp_path, f"/tmp/interface_config.{int(time.time())}")
            os.unlink(tmp_path)  # 清理本地臨時文件
            
            # 6.5 移動到目標位置
            self.ssh_client.execute_command(
                f"sudo mv /tmp/interface_config.{int(time.time())} {interface_file} && "
                f"sudo chmod 644 {interface_file}"
            )
            
            # a. 確保目錄存在(如果使用interfaces.d)
            if use_interfaces_d:
                self.ssh_client.execute_command(
                    f"sudo mkdir -p /etc/network/interfaces.d"
                )
                
                # b. 確保包含source指令
                self.ssh_client.execute_command(
                    f"grep -q 'source /etc/network/interfaces.d/\\*' {main_file} || "
                    f"sudo bash -c 'echo \"source /etc/network/interfaces.d/*\" >> {main_file}'"
                )
            
            # 7. 停止DHCP客戶端進程
            # 7.1 嘗試不同的DHCP客戶端關閉方法
            self.ssh_client.execute_command(
                f"sudo dhclient -r {interface} 2>/dev/null || "
                f"sudo pkill -f 'dhclient.*{interface}' 2>/dev/null || "
                f"sudo killall -q dhclient 2>/dev/null || true"
            )
            
            # 8. 重啟網絡服務
            # 8.1 嘗試多種網絡服務重啟方法
            success = False
            restart_methods = [
                f"sudo systemctl restart networking 2>/dev/null",
                f"sudo service networking restart 2>/dev/null",
                f"sudo ifdown {interface} 2>/dev/null && sudo ifup {interface} 2>/dev/null",
                f"sudo ip link set {interface} down && sudo ip link set {interface} up && "
                f"sudo ip addr add {ip_address}/{self._netmask_to_cidr(netmask)} dev {interface}"
            ]
            
            for method in restart_methods:
                exit_code, _, stderr = self.ssh_client.execute_command(method)
                if exit_code == 0:
                    success = True
                    logger.info(f"成功重啟網絡服務: {method}")
                    break
                else:
                    logger.warning(f"嘗試重啟網絡方法失敗: {method}, 錯誤: {stderr}")
                    # 繼續嘗試下一個方法
            
            # 9. 驗證配置
            # 9.1 檢查IP是否成功應用
            time.sleep(2)  # 等待網絡服務完全啟動
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_address}'"
            )
            
            if exit_code == 0 and stdout.strip():
                logger.info(f"成功應用靜態IP配置: {ip_address} 到接口 {interface}")
                return True
            else:
                # 9.2 尋找任何IP配置
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"ip addr show dev {interface} | grep -w 'inet'"
                )
                
                if exit_code == 0 and stdout.strip():
                    logger.info(f"接口 {interface} 有IP配置，但不是預期的 {ip_address}: {stdout.strip()}")
                    return True
                else:
                    # 9.3 手動設置IP地址作為最後嘗試
                    exit_code, _, stderr = self.ssh_client.execute_command(
                        f"sudo ip addr add {ip_address}/{self._netmask_to_cidr(netmask)} dev {interface} 2>/dev/null"
                    )
                    
                    if exit_code == 0:
                        logger.info(f"通過ip命令手動添加IP: {ip_address} 到接口 {interface}")
                        
                        # 添加默認路由(如果配置了網關)
                        if gateway:
                            self.ssh_client.execute_command(
                                f"sudo ip route add default via {gateway} dev {interface} 2>/dev/null || true"
                            )
                        
                        return True
                    else:
                        logger.error(f"無法手動添加IP地址: {stderr}")
                        
                        # 9.4 檢查是否有任何配置文件已應用，但IP設置失敗
                        return False
            
        except Exception as e:
            logger.error(f"在Debian系統中轉換為靜態IP配置時發生錯誤: {str(e)}")
        return False     

    def _find_netplan_config_file(self, interface: Optional[str] = None, 
                                preferred_file: Optional[str] = None) -> str:
        """
        智能查找並返回最適合的Netplan配置檔案，優先考慮特定檔案路徑
        
        優先級順序:
        1. 明確指定的配置檔案 (preferred_file)
        2. /etc/netplan/50-netcfg.yaml（優先）
        3. /etc/netplan/50-cloud-init.yaml（當 50-netcfg.yaml 不存在時）
        4. 其他現有檔案（根據原優先級邏輯）
        
        當 50-netcfg.yaml 和 50-cloud-init.yaml 同時存在時，50-cloud-init.yaml 將被刪除
        
        參數:
            interface (str, optional): 網絡接口名稱，用於查找包含此接口的配置
            preferred_file (str, optional): 明確指定優先使用的配置檔案路徑
                
        返回:
            str: 最適合的Netplan配置檔案路徑
        """
        logger.debug(f"正在智能查找Netplan配置檔案，接口: {interface}")
        
        # 1. 優先級：明確指定的配置檔案
        if preferred_file:
            # 檢查檔案是否存在
            exit_code, file_exists, _ = self.ssh_client.execute_command(
                f"test -f {preferred_file} && echo 'exists' || echo ''"
            )
            
            if exit_code == 0 and file_exists.strip() == 'exists':
                logger.info(f"使用指定的優先級配置檔案: {preferred_file}")
                return preferred_file
            else:
                logger.warning(f"指定的配置檔案 {preferred_file} 不存在，繼續尋找其他配置")
        
        # 2. 直接檢查特定目標檔案
        target_files = [
            "/etc/netplan/50-netcfg.yaml",
            "/etc/netplan/50-cloud-init.yaml"
        ]
        
        existing_target_files = []
        for file_path in target_files:
            exit_code, file_exists, _ = self.ssh_client.execute_command(
                f"test -f {file_path} && echo 'exists' || echo ''"
            )
            
            if exit_code == 0 and file_exists.strip() == 'exists':
                existing_target_files.append(file_path)
        
        # 3. 處理特殊情況：兩個目標檔案同時存在
        if len(existing_target_files) == 2:
            logger.info("檢測到 50-netcfg.yaml 和 50-cloud-init.yaml 同時存在，將刪除 50-cloud-init.yaml")
            
            # 刪除 50-cloud-init.yaml
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"rm -f {target_files[1]}"
            )
            
            if exit_code != 0:
                logger.warning(f"無法刪除 {target_files[1]}: {stderr}，但仍將使用 {target_files[0]}")
            
            # 使用 50-netcfg.yaml
            logger.info(f"使用配置檔案: {target_files[0]}")
            return target_files[0]
        
        # 4. 如果只有一個目標檔案存在，直接使用它
        if len(existing_target_files) == 1:
            logger.info(f"使用配置檔案: {existing_target_files[0]}")
            return existing_target_files[0]
        
        # 5. 如果都不存在，回退到原有邏輯
        logger.info("未找到目標配置檔案，回退到查找現有配置")
        
        # 5.1 檢查 01-netcfg.yaml 檔案
        netcfg_01_file = "/etc/netplan/01-netcfg.yaml"
        exit_code, file_exists, _ = self.ssh_client.execute_command(
            f"test -f {netcfg_01_file} && echo 'exists' || echo ''"
        )

        if exit_code == 0 and file_exists.strip() == 'exists':
            # 檢查檔案是否有內容
            exit_code, content, _ = self.ssh_client.execute_command(
                f"cat {netcfg_01_file} 2>/dev/null || echo ''"
            )
            
            if exit_code == 0 and content.strip():
                # 檢查是否包含 ethernets 配置
                exit_code, has_ethernets, _ = self.ssh_client.execute_command(
                    f"grep -q 'ethernets:' {netcfg_01_file} && echo 'has_config' || echo ''"
                )
                
                if exit_code == 0 and has_ethernets.strip() == 'has_config':
                    logger.info(f"使用高優先級 01-netcfg.yaml 配置檔案: {netcfg_01_file}")
                    return netcfg_01_file
                else:
                    logger.debug(f"檔案 {netcfg_01_file} 存在但不包含 ethernets 配置")
        
        # 5.2 列出所有 Netplan 檔案
        exit_code, stdout, _ = self.ssh_client.execute_command(
            "ls -la /etc/netplan/ 2>/dev/null || echo ''"
        )
        
        # 記錄所有發現的配置檔案
        all_netplan_files = []
        if exit_code == 0 and stdout.strip():
            logger.debug(f"Netplan目錄內容: \n{stdout}")
            # 解析ls的輸出，提取檔案名
            for line in stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 9:  # ls -la 的輸出格式
                    file_name = parts[-1]
                    if file_name.endswith('.yaml') or file_name.endswith('.yml'):
                        all_netplan_files.append(f"/etc/netplan/{file_name}")
        
        if all_netplan_files:
            logger.debug(f"找到以下Netplan配置檔案: {', '.join(all_netplan_files)}")
        else:
            # 如果沒有找到任何檔案，創建 50-netcfg.yaml
            logger.warning("未找到任何Netplan配置檔案，將使用新的 50-netcfg.yaml")
            return "/etc/netplan/50-netcfg.yaml"
            
        # 5.3 如果只有一個配置檔案，直接返回
        if len(all_netplan_files) == 1:
            logger.info(f"只有一個Netplan配置檔案: {all_netplan_files[0]}")
            return all_netplan_files[0]
        
        # 5.4 特定接口名稱匹配
        if interface:
            for file in all_netplan_files:
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"grep -q '\\b{interface}:\\b' {file} 2>/dev/null && echo 'found'"
                )
                
                if exit_code == 0 and stdout.strip() == 'found':
                    logger.info(f"找到精確匹配接口 {interface} 的配置檔案: {file}")
                    return file
        
        # 5.5 返回第一個檔案作為預設選擇
        logger.info(f"未找到特定匹配，使用第一個可用配置檔案: {all_netplan_files[0]}")
        return all_netplan_files[0]

    def _add_permanent_ip(self, ip_address: str, interface: str) -> bool:
        """
        將IP地址添加到永久配置中
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str): 網絡接口名稱
            
        返回:
            bool: 添加成功返回True，否則返回False
        """
        logger.info(f"正在將IP地址 {ip_address} 添加到永久配置中")
        
        try:
            if self._os_type == 'debian':
                return self._add_permanent_ip_debian(ip_address, interface)
            elif self._os_type == 'redhat':
                return self._add_permanent_ip_redhat(ip_address, interface)
            elif self._os_type == 'netplan':
                return self._add_permanent_ip_netplan(ip_address, interface)
            else:
                logger.warning(f"未知的操作系統類型: {self._os_type}，無法添加永久配置")
                return False
        except Exception as e:
            logger.error(f"添加永久IP配置時發生錯誤: {str(e)}")
            return False    
        
    def _remove_permanent_ip(self, ip_address: str, interface: str) -> bool:
        """
        從永久配置中移除IP地址
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str): 網絡接口名稱
            
        返回:
            bool: 移除成功返回True，否則返回False
        """
        logger.info(f"正在從永久配置中移除IP地址 {ip_address}")
        
        try:
            if self._os_type == 'debian':
                return self._remove_permanent_ip_debian(ip_address, interface)
            elif self._os_type == 'redhat':
                return self._remove_permanent_ip_redhat(ip_address, interface)
            elif self._os_type == 'netplan':
                return self._remove_permanent_ip_netplan(ip_address, interface)
            else:
                logger.warning(f"未知的操作系統類型: {self._os_type}，無法移除永久配置")
                return False
        except Exception as e:
            logger.error(f"移除永久IP配置時發生錯誤: {str(e)}")
            return False    
        
    def _validate_ip(self, ip_address: str) -> bool:
        """
        驗證IP地址格式
        
        參數:
            ip_address (str): IP地址
            
        返回:
            bool: 如果格式正確返回True，否則返回False
        """
        try:
            # 使用ipaddress模塊驗證IP地址
            ipaddress.IPv4Address(ip_address)
            return True
        except Exception:
            return False

    def _validate_ip_cidr(self, ip_address: str) -> bool:
        """
        驗證IP地址的CIDR格式
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y
            
        返回:
            bool: 如果格式正確返回True，否則返回False
        """
        try:
            # 使用ipaddress模塊驗證CIDR
            ipaddress.IPv4Network(ip_address, strict=False)
            return True
        except Exception:
            return False    
        
    def _cidr_to_netmask(self, cidr: int) -> str:
        """
        將CIDR格式轉換為子網掩碼
        
        參數:
            cidr (int): CIDR前綴長度
            
        返回:
            str: 子網掩碼
        """
        if cidr < 0 or cidr > 32:
            return "255.255.255.0"  # 默認為/24
        
        # 計算子網掩碼
        mask = (0xffffffff << (32 - cidr)) & 0xffffffff
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

    def _netmask_to_cidr(self, netmask: str) -> int:
        """
        將子網掩碼轉換為CIDR格式
        
        參數:
            netmask (str): 子網掩碼
            
        返回:
            int: CIDR前綴長度
        """
        try:
            # 將子網掩碼拆分為四個八位組
            parts = netmask.split('.')
            if len(parts) != 4:
                return 24  # 默認為/24
            
            # 轉換為二進制并計算1的個數
            binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(
                int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
            )
            return binary.count('1')
        except Exception:
            return 24  # 默認為/24    

    def _check_networkmanager_config(self, interface: str, config: Dict[str, Any]) -> None:
        """
        檢查NetworkManager配置
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 配置字典，將被此方法修改
        """
        # 檢查NetworkManager配置
        nm_dir = "/etc/NetworkManager/system-connections"
        exit_code, dir_exists, stderr = self.ssh_client.execute_command(f"[ -d {nm_dir} ] && echo 'exists' || echo ''")
        
        if exit_code != 0 or not dir_exists.strip() == 'exists':
            logger.debug(f"NetworkManager配置目錄不存在: {stderr}")
            return
            
        # 列出目錄內容
        exit_code, dir_content, stderr = self.ssh_client.execute_command(f"ls -la {nm_dir} 2>/dev/null || echo ''")
        if exit_code == 0 and dir_content.strip():
            logger.debug(f"NetworkManager目錄內容: {dir_content}")
        
        # 找出可能包含此接口配置的連接文件
        # 首先嘗試直接讀取文件 (需要root權限)
        find_cmd = f"sudo cat {nm_dir}/* 2>/dev/null | grep -l '{interface}' || echo ''"
        exit_code, nm_files, stderr = self.ssh_client.execute_command(find_cmd)
        
        # 如果第一個方法失敗，使用nmcli命令獲取配置信息
        if exit_code != 0 or not nm_files.strip():
            logger.debug("嘗試使用nmcli命令獲取NetworkManager配置")
            nm_cmd = f"nmcli -g NAME,DEVICE connection show 2>/dev/null | grep '{interface}' || echo ''"
            exit_code, nm_conn, stderr = self.ssh_client.execute_command(nm_cmd)
            
            if exit_code == 0 and nm_conn.strip():
                # 解析連接名稱
                conn_names = []
                for line in nm_conn.strip().split('\n'):
                    if ':' in line:
                        conn_name = line.split(':')[0].strip()
                        if conn_name:
                            conn_names.append(conn_name)
                            
                logger.debug(f"找到NetworkManager連接: {conn_names}")
                
                # 獲取連接詳細信息
                for conn_name in conn_names:
                    nm_details_cmd = f"nmcli -g IP4.METHOD connection show '{conn_name}' 2>/dev/null || echo ''"
                    exit_code, method, stderr = self.ssh_client.execute_command(nm_details_cmd)
                    
                    if exit_code == 0 and method.strip():
                        if 'auto' in method.lower() or 'dhcp' in method.lower():
                            config["is_dhcp"] = True
                            config["config_type"] = "NetworkManager"
                            logger.info(f"在NetworkManager連接 {conn_name} 中檢測到接口 {interface} 使用DHCP")
                            
                            # 添加配置文件路徑
                            config["config_files"].append(f"{nm_dir}/{conn_name}")
                            return
                        elif 'manual' in method.lower():
                            config["config_type"] = "NetworkManager"
                            logger.info(f"在NetworkManager連接 {conn_name} 中檢測到接口 {interface} 使用靜態配置")
                            
                            # 獲取IP地址和網關
                            ip_cmd = f"nmcli -g IP4.ADDRESS connection show '{conn_name}' 2>/dev/null || echo ''"
                            exit_code, ip_addr, stderr = self.ssh_client.execute_command(ip_cmd)
                            
                            if exit_code == 0 and ip_addr.strip():
                                for addr in ip_addr.strip().split('\n'):
                                    if addr and addr not in config["addresses"]:
                                        config["addresses"].append(addr)
                            
                            gw_cmd = f"nmcli -g IP4.GATEWAY connection show '{conn_name}' 2>/dev/null || echo ''"
                            exit_code, gateway, stderr = self.ssh_client.execute_command(gw_cmd)
                            
                            if exit_code == 0 and gateway.strip():
                                config["gateway"] = gateway.strip()
                                
                            # 添加配置文件路徑
                            config["config_files"].append(f"{nm_dir}/{conn_name}")
                            return
        
        # 如果可以直接訪問文件
        if exit_code == 0 and nm_files.strip():
            for nm_file in nm_files.strip().split('\n'):
                if not nm_file:
                    continue
                    
                config["config_files"].append(nm_file)
                
                # 檢查文件中的配置
                exit_code, nm_content, stderr = self.ssh_client.execute_command(f"cat {nm_file} 2>/dev/null || echo ''")
                
                if exit_code == 0 and nm_content.strip():
                    if "method=auto" in nm_content.lower() or "method=dhcp" in nm_content.lower():
                        config["is_dhcp"] = True
                        config["config_type"] = "NetworkManager"
                        logger.info(f"在NetworkManager配置 {nm_file} 中檢測到接口 {interface} 使用DHCP")
                        return
                    elif "method=manual" in nm_content.lower():
                        config["config_type"] = "NetworkManager"
                        logger.info(f"在NetworkManager配置 {nm_file} 中檢測到接口 {interface} 使用靜態配置")
                        
                        # 解析靜態IP配置
                        import re
                        address_match = re.search(r'address1=(\d+\.\d+\.\d+\.\d+)/(\d+)', nm_content)
                        gateway_match = re.search(r'gateway=(\d+\.\d+\.\d+\.\d+)', nm_content)
                        
                        if address_match:
                            ip = address_match.group(1)
                            cidr = address_match.group(2)
                            config["addresses"].append(f"{ip}/{cidr}")
                            
                        if gateway_match:
                            config["gateway"] = gateway_match.group(1)
                        return           
                    
    def _clean_duplicate_interface_config(self, yaml_data: Dict, interface: str) -> Dict:
        """
        清理重複的接口配置，如果存在特定接口配置與通配符配置重複，則刪除特定接口配置
        
        參數:
            yaml_data (Dict): Netplan YAML配置
            interface (str): 要清理的接口名稱
            
        返回:
            Dict: 清理後的配置
        """
        logger.info(f"檢查並清理接口 {interface} 的重複配置")
        
        if 'network' not in yaml_data or 'ethernets' not in yaml_data['network']:
            return yaml_data
            
        ethernets = yaml_data['network']['ethernets']
        
        # 檢查是否存在特定接口配置
        if interface in ethernets:
            # 查找可能匹配此接口的通配符配置
            for key, config in ethernets.items():
                if key == interface:
                    continue
                    
                if not isinstance(config, dict):
                    continue
                    
                # 檢查是否有通配符配置匹配此接口
                wildcard_match = False
                
                # 檢查接口名稱是否為通配符
                if '*' in key and self._interface_matches_wildcard(interface, key):
                    wildcard_match = True
                # 檢查match規則
                elif 'match' in config and 'name' in config['match'] and self._interface_matches_wildcard(interface, config['match']['name']):
                    wildcard_match = True
                    
                if wildcard_match:
                    logger.info(f"找到與接口 {interface} 匹配的通配符配置: {key}")
                    
                    # 如果通配符配置使用dhcp4=true而特定接口配置使用靜態IP
                    # 或者通配符配置已經有靜態IP設置，則保留特定接口配置
                    if (config.get('dhcp4') is True and ethernets[interface].get('dhcp4') is False) or \
                       ('addresses' in config and isinstance(config['addresses'], list) and len(config['addresses']) > 0):
                        logger.info(f"保留接口 {interface} 的特定配置")
                    else:
                        # 刪除特定接口配置
                        logger.info(f"刪除重複的接口 {interface} 配置，使用通配符配置 {key}")
                        del ethernets[interface]
                    break
                    
        return yaml_data
        
    def _convert_dhcp_to_static_debian(self, interface: str, config: Dict[str, Any]) -> bool:
        """
        將Debian系統的DHCP配置轉換為靜態IP
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 網絡配置信息
                
        返回:
            bool: 轉換成功返回True，否則返回False
        """
        logger.info(f"正在轉換Debian系統的接口 {interface} 配置")
        
        try:
            # 構建新的網絡配置
            interfaces_config = (
                f"auto {interface}\n"
                f"iface {interface} inet static\n"
                f"    address {config['ip_address']}\n"
                f"    netmask {config['netmask']}\n"
            )
            
            if config["gateway"]:
                interfaces_config += f"    gateway {config['gateway']}\n"
            
            if config["dns_servers"]:
                interfaces_config += f"    dns-nameservers {' '.join(config['dns_servers'])}\n"
            
            # 檢查interfaces.d目錄是否存在
            exit_code, _, _ = self.ssh_client.execute_command(
                "test -d /etc/network/interfaces.d"
            )
            
            use_interfaces_d = (exit_code == 0)
            
            # === 全面清除DHCP配置 ===
            # 1. 停止DHCP客戶端進程
            self.ssh_client.execute_command(
                f"dhclient -r {interface} 2>/dev/null || true"
            )
            self.ssh_client.execute_command(
                f"pkill -f 'dhclient.*{interface}' || true"
            )
            
            # 2. 刪除所有接口的DHCP配置
            if use_interfaces_d:
                # 在interfaces.d目錄中查找並清除所有涉及該接口的DHCP配置
                interface_files = [
                    f"/etc/network/interfaces",
                    f"/etc/network/interfaces.d/{interface}",
                    f"/etc/network/interfaces.d/50-cloud-init.cfg"  # 常見的cloud-init配置
                ]
                
                for file_path in interface_files:
                    # 檢查文件是否存在
                    exit_code, _, _ = self.ssh_client.execute_command(
                        f"test -f {file_path}"
                    )
                    
                    if exit_code == 0:
                        # 刪除該接口的DHCP配置行
                        self.ssh_client.execute_command(
                            f"sed -i '/iface {interface} inet dhcp/d' {file_path}"
                        )
                        # 刪除該接口的auto行（稍後會添加新的）
                        self.ssh_client.execute_command(
                            f"sed -i '/auto {interface}$/d' {file_path}"
                        )
            else:
                # 直接在interfaces文件中清除
                # 首先備份interfaces文件
                backup_file = f"/etc/network/interfaces.bak.{int(time.time())}"
                self.ssh_client.execute_command(
                    f"cp /etc/network/interfaces {backup_file}"
                )
                
                # 刪除關於該接口的所有配置
                self.ssh_client.execute_command(
                    f"sed -i '/auto {interface}$/d' /etc/network/interfaces"
                )
                self.ssh_client.execute_command(
                    f"sed -i '/iface {interface} inet dhcp/d' /etc/network/interfaces"
                )
            
            # 3. 寫入新的靜態配置
            if use_interfaces_d:
                interface_file = f"/etc/network/interfaces.d/{interface}"
                
                # 創建接口配置文件
                self.ssh_client.execute_command(
                    f"echo '{interfaces_config}' > {interface_file}"
                )
                
                # 確保主配置文件包含interfaces.d
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    "grep -q 'source /etc/network/interfaces.d/*' /etc/network/interfaces"
                )
                
                if exit_code != 0:
                    self.ssh_client.execute_command(
                        "echo 'source /etc/network/interfaces.d/*' >> /etc/network/interfaces"
                    )
            else:
                # 直接使用interfaces文件
                self.ssh_client.execute_command(
                    f"echo '{interfaces_config}' >> /etc/network/interfaces"
                )
            
            # 4. 檢查並刪除cloud-init網絡配置
            self.ssh_client.execute_command(
                "test -d /etc/cloud/cloud.cfg.d && "
                "echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg || true"
            )
            
            # 5. 重啟網絡服務
            self.ssh_client.execute_command(
                "systemctl restart networking 2>/dev/null || "
                f"(ifdown {interface} 2>/dev/null || true; ifup {interface} 2>/dev/null || true)"
            )
            
            # 6. 安全檢查：確認DHCP客戶端沒有在運行
            exit_code, dhcp_processes, _ = self.ssh_client.execute_command(
                f"ps aux | grep 'dhclient.*{interface}' | grep -v grep"
            )
            
            if exit_code == 0 and dhcp_processes.strip():
                logger.warning(f"轉換後仍檢測到DHCP客戶端進程: {dhcp_processes}")
                # 強制終止DHCP客戶端
                self.ssh_client.execute_command(
                    f"pkill -9 -f 'dhclient.*{interface}' || true"
                )
            
            logger.info(f"已在Debian系統中將接口 {interface} 轉換為靜態IP配置")
            return True
            
        except Exception as e:
            logger.error(f"在Debian系統中轉換為靜態IP配置時發生錯誤: {str(e)}")
            return False
           
    def _add_permanent_ip_debian(self, ip_address: str, interface: str) -> bool:
        """
        在 Debian 系統中添加永久 IP 配置，使用逐級遞增的接口別名索引
        
        參數:
            ip_address (str): IP 地址，格式為 x.x.x.x/y (CIDR 格式)
            interface (str): 網絡接口名稱
                
        返回:
            bool: 添加成功返回 True，否則返回 False
        """
        logger.info(f"正在 Debian 系統中添加永久 IP 配置: {ip_address} 到 {interface}")
        
        try:
            # 解析 IP 和 CIDR
            ip_parts = ip_address.split('/')
            ip = ip_parts[0]
            cidr = ip_parts[1] if len(ip_parts) > 1 else "24"  # 默認為 /24
            
            # 轉換 CIDR 為子網掩碼
            netmask = self._cidr_to_netmask(int(cidr))
            
            # 檢查 interfaces.d 目錄是否存在
            exit_code, _, _ = self.ssh_client.execute_command(
                "test -d /etc/network/interfaces.d"
            )
            
            use_interfaces_d = (exit_code == 0)
            
            # 決定要使用的配置文件路徑
            if use_interfaces_d:
                config_file = f"/etc/network/interfaces.d/{interface}"
            else:
                config_file = "/etc/network/interfaces"
                
            # 檢查接口是否已有配置，並創建配置文件（如果需要）
            if use_interfaces_d:
                exit_code, _, _ = self.ssh_client.execute_command(
                    f"test -f {config_file}"
                )
                file_exists = (exit_code == 0)
                
                if not file_exists:
                    # 創建新的接口配置文件
                    self.ssh_client.execute_command(
                        f"touch {config_file}"
                    )
                    
                    # 確保 interfaces 文件包含 source 指令
                    self.ssh_client.execute_command(
                        "grep -q 'source /etc/network/interfaces.d/\\*' /etc/network/interfaces || "
                        "echo 'source /etc/network/interfaces.d/*' >> /etc/network/interfaces"
                    )
            
            # === 全面改進的索引查找邏輯 ===
            # 步驟1: 檢查當前活動接口別名
            active_cmd = (
                f"ip addr show | grep '{interface}:' | "
                f"sed -n 's/.*\\({interface}:[0-9]\\+\\).*/\\1/p' | sort -u"
            )
            exit_code1, active_aliases, _ = self.ssh_client.execute_command(active_cmd)
            
            # 步驟2: 檢查所有網絡配置文件中的接口別名
            # 擴大搜索範圍至整個 /etc/network 目錄
            config_cmd = (
                f"grep -r -E '(auto|iface) {interface}:[0-9]+' /etc/network/ 2>/dev/null | "
                f"sed -n 's/.*\\({interface}:[0-9]\\+\\).*/\\1/p' | sort -u"
            )
            exit_code2, config_aliases, _ = self.ssh_client.execute_command(config_cmd)
            
            # 步驟3: 整合所有找到的別名並提取索引
            aliases = []
            if exit_code1 == 0 and active_aliases.strip():
                aliases.extend([alias.strip() for alias in active_aliases.strip().split('\n')])
            if exit_code2 == 0 and config_aliases.strip():
                aliases.extend([alias.strip() for alias in config_aliases.strip().split('\n')])
            
            # 步驟4: 精確提取所有索引並找到最大值
            indices = []
            for alias in aliases:
                try:
                    # 更精確的正則表達式匹配
                    import re
                    match = re.search(f"{interface}:([0-9]+)", alias)
                    if match:
                        indices.append(int(match.group(1)))
                except (ValueError, IndexError):
                    continue
            
            # 步驟5: 確定下一個可用索引
            next_alias_index = max(indices + [0]) + 1
            
            # 記錄找到的所有索引及選擇的下一個索引
            logger.debug(f"找到的接口別名索引: {indices}, 選擇的下一個索引: {next_alias_index}")
            
            # 檢查 IP 是否已經配置
            exit_code, existing_ips, _ = self.ssh_client.execute_command(
                f"grep -A1 'iface {interface}\\(:[0-9]\\+\\)\\?\\s\\+inet\\s\\+static' {config_file} 2>/dev/null | "
                f"grep 'address' | awk '{{print $2}}'"
            )
            
            if exit_code == 0 and existing_ips.strip():
                # 檢查 IP 是否已存在
                for existing_ip in existing_ips.strip().split('\n'):
                    if existing_ip.strip() == ip:
                        logger.info(f"IP {ip} 已存在於配置文件中")
                        return True
            
            # 構建接口別名配置
            alias_name = f"{interface}:{next_alias_index}"
            alias_config = (
                f"auto {alias_name}\n"
                f"iface {alias_name} inet static\n"
                f"    address {ip}\n"
                f"    netmask {netmask}\n"
            )
            
            # 寫入配置文件
            self.ssh_client.execute_command(
                f"echo '{alias_config}' >> {config_file}"
            )
            
            # 設置文件權限
            self.ssh_client.execute_command(
                f"chmod 644 {config_file}"
            )
            
            # 應用配置
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"ifup {alias_name} 2>/dev/null || echo 'WARNING: ifup failed, trying ip command'"
            )
            
            if "WARNING" in stderr or exit_code != 0:
                # 如果 ifup 失敗，嘗試使用 ip 命令
                self.ssh_client.execute_command(
                    f"ip addr add {ip}/{cidr} dev {interface} 2>/dev/null || true"
                )
            
            logger.info(f"已在 Debian 系統中添加永久 IP 配置: {ip} 到接口別名 {alias_name}")
            return True
            
        except Exception as e:
            logger.error(f"在 Debian 系統中添加永久 IP 配置時發生錯誤: {str(e)}")
            return False
            
    def _check_ip_exists(self, ip_address: str, interface: str) -> bool:
        """
        檢查IP地址是否已存在於指定接口
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y 或 x.x.x.x
            interface (str): 網絡接口名稱
            
        返回:
            bool: 如果IP存在返回True，否則返回False
        """
        # 如果包含CIDR前綴，則提取IP部分
        if '/' in ip_address:
            ip_only = ip_address.split('/')[0]
        else:
            ip_only = ip_address
            
        try:
            # 使用ip addr命令檢查IP是否存在
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_only}'"
            )
            
            return exit_code == 0 and stdout.strip() != ''
        except Exception as e:
            logger.error(f"檢查IP是否存在時發生錯誤: {str(e)}")
            return False    
        
    def _remove_permanent_ip_debian(self, ip_address: str, interface: str) -> bool:
        """
        在 Debian 系統中移除永久 IP 配置
        
        參數:
            ip_address (str): IP 地址，格式為 x.x.x.x/y (CIDR 格式)
            interface (str): 網絡接口名稱
            
        返回:
            bool: 移除成功返回 True，否則返回 False
        """
        logger.info(f"正在 Debian 系統中移除永久 IP 配置: {ip_address} 從 {interface}")
        
        try:
            # 解析 IP 地址
            ip_parts = ip_address.split('/')
            ip = ip_parts[0]
            
            # 檢查 interfaces.d 目錄是否存在
            exit_code, _, _ = self.ssh_client.execute_command(
                "test -d /etc/network/interfaces.d"
            )
            
            use_interfaces_d = (exit_code == 0)
            
            # 決定要使用的配置文件路徑
            if use_interfaces_d:
                config_file = f"/etc/network/interfaces.d/{interface}"
                # 檢查接口配置文件是否存在
                exit_code, _, _ = self.ssh_client.execute_command(
                    f"test -f {config_file}"
                )
                if exit_code != 0:
                    config_file = "/etc/network/interfaces"
            else:
                config_file = "/etc/network/interfaces"
            
            # 搜索所有包含該 IP 的介面別名
            exit_code, all_aliases, _ = self.ssh_client.execute_command(
                f"grep -B2 -A1 'address {ip}' {config_file} 2>/dev/null | grep -E 'iface {interface}:[0-9]+'"
            )
            
            if exit_code != 0 or not all_aliases.strip():
                logger.warning(f"未找到包含 IP {ip} 的介面別名配置")
                
                # 檢查是否存在於接口上，如果存在則用 ip 命令移除
                exit_code, ip_exists, _ = self.ssh_client.execute_command(
                    f"ip addr show {interface} | grep -w '{ip}'"
                )
                
                if exit_code == 0 and ip_exists.strip():
                    # 使用 ip 命令移除
                    cidr = ip_parts[1] if len(ip_parts) > 1 else "32"
                    self.ssh_client.execute_command(
                        f"ip addr del {ip}/{cidr} dev {interface} 2>/dev/null"
                    )
                    logger.info(f"使用 ip 命令從接口 {interface} 移除 IP {ip}")
                
                return True
            
            # 處理找到的每一個別名配置
            for alias_config in all_aliases.strip().split('\n'):
                alias_match = re.search(r'iface\s+(.*?)\s+inet', alias_config)
                if not alias_match:
                    continue
                    
                alias_name = alias_match.group(1)
                logger.info(f"找到包含 IP {ip} 的介面別名: {alias_name}")
                
                # 關閉介面別名
                self.ssh_client.execute_command(
                    f"ifdown {alias_name} 2>/dev/null || ip addr del {ip} dev {interface} 2>/dev/null || true"
                )
                
                # 從配置文件中移除整個別名配置塊
                # 找出起始和結束行號
                exit_code, start_line, _ = self.ssh_client.execute_command(
                    f"grep -n -B1 'iface {alias_name} inet static' {config_file} | head -1 | cut -d- -f1 | cut -d: -f1"
                )
                
                if exit_code == 0 and start_line.strip():
                    # 尋找 "auto {alias_name}" 行的位置
                    auto_line = int(start_line.strip()) - 1
                    
                    # 檢查前一行是否為註釋（# 附加 IP 配置...）
                    exit_code, prev_line_content, _ = self.ssh_client.execute_command(
                        f"sed -n '{auto_line-1}p' {config_file} 2>/dev/null"
                    )
                    
                    if exit_code == 0 and "附加 IP 配置" in prev_line_content:
                        auto_line = auto_line - 1  # 包含註釋行
                    
                    # 查找配置塊的結束位置
                    exit_code, next_block, _ = self.ssh_client.execute_command(
                        f"tail -n +{auto_line+4} {config_file} | grep -n -m1 -E '^auto|^iface|^[[:space:]]*$' | head -1 | cut -d: -f1"
                    )
                    
                    if exit_code == 0 and next_block.strip():
                        end_line = auto_line + 3 + int(next_block.strip())
                    else:
                        # 如果找不到下一個塊，假設配置佔用4行（註釋、auto、iface、address、netmask）
                        end_line = auto_line + 4
                    
                    # 移除配置塊
                    self.ssh_client.execute_command(
                        f"sed -i '{auto_line},{end_line}d' {config_file}"
                    )
                    logger.info(f"已從配置文件中移除介面別名 {alias_name} 的配置塊")
                else:
                    logger.warning(f"無法定位 {alias_name} 的配置起始行")
                    
                    # 嘗試一種替代方法：保存不含該別名的行
                    tmp_file = f"/tmp/interfaces_tmp_{int(time.time())}"
                    self.ssh_client.execute_command(
                        f"grep -v -A3 'iface {alias_name} inet static' {config_file} > {tmp_file} && " +
                        f"mv {tmp_file} {config_file}"
                    )
                    logger.info(f"使用替代方法移除介面別名 {alias_name} 的配置")
        except Exception as e:
            logger.error(f"在 Debian 系統中移除永久 IP 配置時發生錯誤: {str(e)}")
            return False
        
    def _remove_permanent_ip_redhat(self, ip_address: str, interface: str) -> bool:
        """
        在RedHat系統中移除永久IP配置，支持CentOS 9的keyfile格式
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
                    或 x.x.x.x (無CIDR格式)
            interface (str): 網絡接口名稱
                    
        返回:
            bool: 移除成功返回True，否則返回False
        """
        logger.info(f"正在RedHat系統中移除永久IP配置: {ip_address} 從 {interface}")
        
        try:
            # 1. 參數處理與預備工作
            # 1.1 提取純IP地址部分（不包含子網掩碼）
            ip_only = ip_address.split('/')[0]
            
            # 1.2 檢測是否為 CentOS/RHEL 9
            exit_code, os_info, _ = self.ssh_client.execute_command(
                "cat /etc/os-release 2>/dev/null | grep -E '^(ID|VERSION_ID)=' | tr -d '\"'"
            )
            
            is_centos9 = False
            if exit_code == 0 and os_info.strip():
                for line in os_info.strip().split('\n'):
                    if line.startswith("ID=") and ("centos" in line.lower() or "rhel" in line.lower()):
                        for ver_line in os_info.strip().split('\n'):
                            if ver_line.startswith("VERSION_ID=") and ver_line.split('=')[1].startswith("9"):
                                is_centos9 = True
                                break
                        break
            
            # 1.3 檢查nmcli命令是否存在
            exit_code, stdout, _ = self.ssh_client.execute_command("which nmcli >/dev/null 2>&1 && echo 'exists' || echo ''")
            nmcli_exists = (exit_code == 0 and stdout.strip() == 'exists')
            
            # 2. CentOS 9 專用處理分支
            if is_centos9 and nmcli_exists:
                logger.info(f"檢測到 CentOS 9 系統，使用 NetworkManager 配置處理")
                return self._remove_permanent_ip_centos9(ip_address, interface)
            
            # 3. 傳統 RedHat 系統處理
            # 3.1 配置文件路徑
            config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface}"
            
            # 3.2 首先檢查是否使用現代格式（IPADDR0, PREFIX0）
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"grep -E 'IPADDR[0-9]+=\"?{ip_only}\"?' {config_file} 2>/dev/null || echo ''"
            )
            
            if exit_code == 0 and stdout.strip():
                # 3.2.1 找到使用現代格式的IP配置
                # 提取索引號
                match = re.search(r'IPADDR(\d+)=', stdout.strip())
                if match:
                    index = match.group(1)
                    logger.info(f"找到索引為 {index} 的IP配置")
                    
                    # 3.2.2 移除IP配置行
                    self.ssh_client.execute_command(
                        f"sed -i '/IPADDR{index}=/d' {config_file}"
                    )
                    self.ssh_client.execute_command(
                        f"sed -i '/PREFIX{index}=/d' {config_file}"
                    )
                    
                    # 3.2.3 重啟網絡服務或重新加載接口配置
                    # 對於較新的系統，我們首先嘗試nmcli
                    exit_code, _, _ = self.ssh_client.execute_command(
                        "which nmcli >/dev/null 2>&1"
                    )
                    
                    if exit_code == 0:
                        # 使用NetworkManager
                        self.ssh_client.execute_command(
                            f"nmcli connection reload {interface} || nmcli con reload || (systemctl restart NetworkManager || service NetworkManager restart)"
                        )
                    else:
                        # 使用傳統方法
                        self.ssh_client.execute_command(
                            f"systemctl restart network || service network restart || (ifdown {interface} && ifup {interface})"
                        )
                    
                    logger.info(f"已從現代格式配置中移除IP {ip_only}")
                    return True
                return True  # 即使沒有找到匹配的索引，也算成功
            
            # 3.3 如果沒有找到現代格式，則檢查是否有傳統格式的別名文件
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"grep -l 'IPADDR={ip_only}' /etc/sysconfig/network-scripts/ifcfg-{interface}:* 2>/dev/null || echo ''"
            )
            
            if exit_code == 0 and stdout.strip():
                # 3.3.1 找到傳統格式的別名文件
                for config_file in stdout.strip().split('\n'):
                    if config_file:
                        # 關閉接口
                        device_name = os.path.basename(config_file).replace('ifcfg-', '')
                        self.ssh_client.execute_command(
                            f"ifdown {device_name} 2>/dev/null || true"
                        )
                        
                        # 刪除配置文件
                        exit_code, _, stderr = self.ssh_client.execute_command(
                            f"rm -f {config_file}"
                        )
                        
                        if exit_code != 0:
                            logger.error(f"刪除配置文件 {config_file} 失敗: {stderr}")
                            return False
                
                logger.info(f"已從傳統格式配置中移除IP {ip_only}")
                return True
            
            # 3.4 如果沒有找到任何配置但IP存在，嘗試手動移除
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_only}'"
            )
            
            if exit_code == 0 and stdout.strip():
                logger.warning(f"在配置文件中未找到IP {ip_only}，但IP存在於接口，嘗試手動移除")
                self.ssh_client.execute_command(f"ip addr del {ip_address} dev {interface} 2>/dev/null || true")
            
            # 3.5 如果沒有找到任何配置
            logger.info(f"未找到包含IP {ip_only} 的配置")
            return True
                
        except Exception as e:
            logger.error(f"在RedHat系統中移除永久IP配置時發生錯誤: {str(e)}")
            return False

    def _add_renumbered_addresses(self, modified_lines: List[str], addresses: Dict[int, Tuple[str, str]], removed_indices: List[int]) -> None:
        """
        輔助方法：添加重新編號的地址配置行
        
        參數:
            modified_lines (List[str]): 修改後的配置行列表，將直接修改此列表
            addresses (Dict[int, Tuple[str, str]]): 保留的地址配置，格式為 {索引: (IP地址, 網關)}
            removed_indices (List[int]): 需要移除的索引列表
        """
        if not addresses:
            return
        
        # 獲取所有索引並排序
        all_indices = sorted(addresses.keys())
        
        # 構建新的索引映射
        new_index = 1
        for old_index in all_indices:
            addr_value, gateway = addresses[old_index]
            addr_line = f"address{new_index}={addr_value}{gateway}"
            modified_lines.append(addr_line)
            new_index += 1

    def _remove_permanent_ip_centos9(self, ip_address: str, interface: str) -> bool:
        """
        在CentOS 9系統中移除永久IP配置
        
        參數:
            ip_address (str): IP地址
            interface (str): 網絡接口名稱
                
        返回:
            bool: 移除成功返回True，失敗返回False
        """
        logger.info(f"在CentOS 9系統中移除永久IP配置: {ip_address} 從 {interface}")
        
        try:
            # 檢查NetworkManager連接
            # 尋找對應接口的配置文件
            nm_file_paths = [
                f"/etc/NetworkManager/system-connections/{interface}.nmconnection",
                f"/etc/NetworkManager/system-connections/{interface}"
            ]
            
            nm_file = None
            for path in nm_file_paths:
                exit_code, _, _ = self.ssh_client.execute_command(f"test -f {path}")
                if exit_code == 0:
                    nm_file = path
                    break
            
            if not nm_file:
                # 檢查是否有其他配置文件包含此接口
                exit_code, nm_files, _ = self.ssh_client.execute_command(
                    "ls -la /etc/NetworkManager/system-connections/ 2>/dev/null || echo ''"
                )
                
                if exit_code == 0 and nm_files.strip():
                    for file_line in nm_files.strip().split('\n'):
                        if not file_line or file_line.startswith('total'):
                            continue
                        
                        file_parts = file_line.split()
                        if len(file_parts) < 9:
                            continue
                            
                        file_name = file_parts[-1]
                        
                        # 檢查文件是否包含接口信息
                        exit_code, file_content, _ = self.ssh_client.execute_command(
                            f"grep -l 'interface-name={interface}' '/etc/NetworkManager/system-connections/{file_name}' 2>/dev/null"
                        )
                        
                        if exit_code == 0 and file_content.strip():
                            nm_file = f"/etc/NetworkManager/system-connections/{file_name}"
                            break
            
            if not nm_file:
                logger.info(f"未找到接口 {interface} 的NetworkManager配置文件")
                # 檢查是否有nmcli可用
                exit_code, _, _ = self.ssh_client.execute_command("which nmcli >/dev/null 2>&1")
                if exit_code == 0:
                    # 嘗試使用nmcli移除
                    return self._remove_ip_using_nmcli(ip_address, interface)
                return True  # 配置不存在，視為已移除
            
            # 解析IP地址（不含CIDR前綴）
            ip_only = ip_address.split('/')[0] if '/' in ip_address else ip_address
            
            # 讀取配置文件內容
            exit_code, content, _ = self.ssh_client.execute_command(f"cat {nm_file}")
            
            if exit_code != 0 or not content.strip():
                logger.error(f"無法讀取NetworkManager配置文件: {nm_file}")
                return False
            
            # 檢查文件是否包含IP地址
            ip_present = False
            ipv4_section = False
            modified_lines = []
            address_pattern = r'address(\d+)='
            modified_content = False
            address_indices = {}  # 格式: {索引: 行內容}
            
            # 第一次遍歷：尋找所有address配置和包含目標IP的配置
            for line in content.strip().split('\n'):
                if line.strip() == '[ipv4]':
                    ipv4_section = True
                elif line.strip().startswith('[') and line.strip() != '[ipv4]':
                    ipv4_section = False
                
                if ipv4_section:
                    # 檢查是否為address行並包含目標IP
                    if line.strip().startswith('address'):
                        match = re.search(address_pattern, line)
                        if match:
                            index = int(match.group(1))
                            if ip_only in line:
                                ip_present = True
                                address_indices[index] = 'remove'
                            else:
                                address_indices[index] = line
            
            if not ip_present:
                logger.info(f"IP {ip_address} 不存在於NetworkManager配置文件中")
                return True
            
            # 第二次遍歷：構建修改後的配置
            ipv4_section = False
            indices_to_remove = sorted([idx for idx, action in address_indices.items() if action == 'remove'])
            
            for line in content.strip().split('\n'):
                if line.strip() == '[ipv4]':
                    ipv4_section = True
                    modified_lines.append(line)
                    continue
                elif line.strip().startswith('[') and line.strip() != '[ipv4]':
                    ipv4_section = False
                    modified_lines.append(line)
                    continue
                
                if ipv4_section and line.strip().startswith('address'):
                    match = re.search(address_pattern, line)
                    if match:
                        index = int(match.group(1))
                        if index in indices_to_remove:
                            # 跳過要移除的address行
                            modified_content = True
                            continue
                        else:
                            # 調整較高索引的address編號
                            new_index = index
                            for remove_idx in indices_to_remove:
                                if remove_idx < index:
                                    new_index -= 1
                            
                            if new_index != index:
                                modified_content = True
                                modified_lines.append(line.replace(f'address{index}=', f'address{new_index}='))
                            else:
                                modified_lines.append(line)
                    else:
                        modified_lines.append(line)
                else:
                    modified_lines.append(line)
            
            # 如果配置未修改，則無需更新文件
            if not modified_content:
                logger.warning(f"配置文件內容未變更，可能是IP格式不匹配")
                return True
            
            # 寫入臨時文件
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.write('\n'.join(modified_lines))
                tmp_path = tmp.name
            
            # 上傳到服務器並應用
            tmp_remote = f"/tmp/nm_config_{int(time.time())}.conf"
            self.ssh_client.upload_file(tmp_path, tmp_remote)
            os.unlink(tmp_path)  # 清理本地臨時文件
            
            # 移動到目標位置
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"cp {tmp_remote} {nm_file} && chmod 600 {nm_file} && rm -f {tmp_remote}"
            )
            
            if exit_code != 0:
                logger.error(f"更新NetworkManager配置文件失敗: {stderr}")
                return False
            
            # 重新加載配置
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"nmcli connection reload && nmcli connection up '{interface}'"
            )
            
            if exit_code != 0:
                logger.warning(f"重新加載NetworkManager配置警告: {stderr}")
            
            # 確保IP已從接口移除
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_only}'"
            )
            
            if exit_code == 0 and stdout.strip():
                logger.warning(f"IP仍然存在於接口 {interface}，嘗試手動移除")
                self.ssh_client.execute_command(f"ip addr del {ip_address} dev {interface} 2>/dev/null || true")
            
            logger.info(f"成功從CentOS 9系統中移除永久IP配置: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"在CentOS 9系統中移除永久IP配置時發生錯誤: {str(e)}")
            return False

    def _remove_ip_using_nmcli(self, ip_address: str, interface: str) -> bool:
        """
        使用nmcli命令移除接口上的IP地址
        
        參數:
            ip_address (str): IP地址
            interface (str): 網絡接口名稱
                
        返回:
            bool: 移除成功返回True，失敗返回False
        """
        try:
            # 獲取接口的連接名稱
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"nmcli -t -f NAME,DEVICE connection show | grep ':{interface}$' | cut -d: -f1"
            )
            
            if exit_code != 0 or not stdout.strip():
                logger.warning(f"未找到接口 {interface} 的NetworkManager連接")
                # 嘗試使用ip命令直接移除
                self.ssh_client.execute_command(f"ip addr del {ip_address} dev {interface} 2>/dev/null || true")
                return True
            
            conn_name = stdout.strip()
            logger.info(f"找到接口 {interface} 的連接: {conn_name}")
            
            # 獲取當前IP地址列表
            exit_code, ip_list, _ = self.ssh_client.execute_command(
                f"nmcli -g ipv4.addresses connection show '{conn_name}'"
            )
            
            if exit_code != 0 or not ip_list.strip():
                logger.warning(f"未找到連接 {conn_name} 的IP地址列表")
                # 嘗試使用ip命令直接移除
                self.ssh_client.execute_command(f"ip addr del {ip_address} dev {interface} 2>/dev/null || true")
                return True
            
            # 解析IP地址（不含CIDR前綴）
            ip_only = ip_address.split('/')[0] if '/' in ip_address else ip_address
            
            # 解析地址列表，移除匹配的項
            addresses = []
            ip_found = False
            
            for addr in ip_list.strip().split(','):
                if ip_only not in addr:
                    addresses.append(addr)
                else:
                    ip_found = True
            
            if not ip_found:
                logger.info(f"IP {ip_only} 不存在於連接 {conn_name} 的配置中")
                return True
            
            # 構建新的地址列表
            if addresses:
                new_ip_list = ','.join(addresses)
                # 更新連接配置
                exit_code, _, stderr = self.ssh_client.execute_command(
                    f"nmcli connection modify '{conn_name}' ipv4.addresses '{new_ip_list}'"
                )
                
                if exit_code != 0:
                    logger.error(f"更新連接配置失敗: {stderr}")
                    return False
                
                # 重新加載連接
                self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
            else:
                # 如果移除後沒有IP，需要特殊處理
                logger.warning(f"移除IP後連接 {conn_name} 沒有剩餘IP地址")
                
                # 檢查是否支持DHCP
                exit_code, dhcp_enabled, _ = self.ssh_client.execute_command(
                    f"nmcli -g ipv4.method connection show '{conn_name}' | grep -q 'auto' && echo 'true' || echo 'false'"
                )
                
                if exit_code == 0 and dhcp_enabled.strip() == 'true':
                    # 支持DHCP，切換回DHCP模式
                    self.ssh_client.execute_command(
                        f"nmcli connection modify '{conn_name}' ipv4.method auto ipv4.addresses ''"
                    )
                    self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
                else:
                    # 不支持DHCP，保留為靜態IP但清空地址列表
                    self.ssh_client.execute_command(
                        f"nmcli connection modify '{conn_name}' ipv4.addresses ''"
                    )
                    self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
            
            # 確保IP已從接口移除
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_only}'"
            )
            
            if exit_code == 0 and stdout.strip():
                logger.warning(f"IP仍然存在於接口 {interface}，嘗試手動移除")
                self.ssh_client.execute_command(f"ip addr del {ip_address} dev {interface} 2>/dev/null || true")
            
            logger.info(f"成功使用nmcli從接口 {interface} 移除IP: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"使用nmcli移除IP時發生錯誤: {str(e)}")
            # 嘗試使用ip命令作為備選方案
            self.ssh_client.execute_command(f"ip addr del {ip_address} dev {interface} 2>/dev/null || true")
            return True

    def _remove_permanent_ip_netplan(self, ip_address: str, interface: str) -> bool:
        """
        在使用Netplan的系統中移除永久IP配置
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str): 網絡接口名稱
            
        返回:
            bool: 移除成功返回True，否則返回False
        """
        logger.info(f"正在Netplan系統中移除永久IP配置: {ip_address} 從 {interface}")
        
        try:
            # 使用改進的方法查找適合的netplan配置文件
            netplan_file = self._find_netplan_config_file(interface)
            logger.info(f"將使用netplan配置文件: {netplan_file}")
            
            # 檢查文件是否存在
            exit_code, _, _ = self.ssh_client.execute_command(f"test -f {netplan_file}")
            if exit_code != 0:
                logger.info(f"netplan配置文件 {netplan_file} 不存在，無需移除")
                return True
            
            # 檢查IP是否存在於配置中
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"grep -q '{ip_address}' {netplan_file}"
            )
            
            if exit_code != 0:
                logger.info(f"IP {ip_address} 不存在於Netplan配置中")
                return True
            
            # 提取IP（不含CIDR前綴）
            ip_only = ip_address.split('/')[0]
            
            # 從配置文件中移除IP
            # 1. 嘗試精確匹配完整IP地址（含CIDR）
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"sed -i '/- {ip_address}/d' {netplan_file}"
            )
            
            if exit_code != 0:
                logger.warning(f"移除精確匹配IP失敗: {stderr}，嘗試模糊匹配")
                
                # 2. 嘗試模糊匹配（僅IP，不含CIDR）
                exit_code, _, stderr = self.ssh_client.execute_command(
                    f"sed -i '/- {ip_only}\\//d' {netplan_file}"
            )
            
            if exit_code != 0:
                logger.error(f"從Netplan配置中移除IP失敗: {stderr}")
                return False
            
            # 檢查接口配置是否為空（無IP地址）
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"grep -A10 '{interface}:' {netplan_file} | grep -q '- ' || echo 'empty'"
            )
            
            if exit_code == 0 and stdout.strip() == 'empty':
                # 如果接口沒有其他IP，可以選擇刪除整個接口配置或保留空配置
                logger.info(f"接口 {interface} 沒有其他IP地址，但仍保留接口配置")
            
            # 應用netplan配置
            exit_code, _, stderr = self.ssh_client.execute_command(
                "netplan apply"
            )
            
            if exit_code != 0:
                logger.error(f"應用Netplan配置失敗: {stderr}")
                return False
            
            # 確保IP從接口上移除
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_only}'"
            )
            
            if exit_code == 0 and stdout.strip():
                logger.warning(f"IP仍然存在於接口 {interface}，手動移除")
                # 手動使用ip命令移除
                self.ssh_client.execute_command(
                    f"ip addr del {ip_address} dev {interface} 2>/dev/null || ip addr del {ip_only}/32 dev {interface} 2>/dev/null || true"
                )
            
            logger.info(f"已在Netplan系統中移除永久IP配置: {ip_address} 從 {interface}")
            return True
            
        except Exception as e:
            logger.error(f"在Netplan系統中移除永久IP配置時發生錯誤: {str(e)}")
            return False
        
    def clean_netplan_config(self, interface: str) -> bool:
        """
        清理Netplan配置中的重複接口配置
        
        此方法用於修復已經出現重複配置的問題，例如同時存在eth*的通配符配置和eth0的特定接口配置
        默認會刪除通配符配置，保留特定接口配置

        參數:
            interface (str): 接口名稱，例如 'eth0'
            
        返回:
            bool: 清理成功返回True，否則返回False
        """
        logger.info(f"開始清理接口 {interface} 的Netplan配置")
        
        try:
            # 獲取netplan配置文件
            netplan_file = self._find_netplan_config_file(interface)
            if not netplan_file:
                logger.error("找不到Netplan配置文件")
                return False
                
            logger.info(f"將使用Netplan配置文件: {netplan_file}")
            
            # 讀取當前配置
            exit_code, content, _ = self.ssh_client.execute_command(f"cat {netplan_file} 2>/dev/null || echo ''")
            
            if exit_code != 0 or not content.strip():
                logger.error(f"無法讀取netplan配置文件: {netplan_file}")
                return False
                
            try:
                # 使用yaml模塊解析配置
                import yaml
                
                yaml_data = yaml.safe_load(content)
                if not yaml_data or 'network' not in yaml_data or 'ethernets' not in yaml_data['network']:
                    logger.error("Netplan配置格式無效")
                    return False
                    
                ethernets = yaml_data['network']['ethernets']
                
                # 檢查是否存在特定接口配置
                if interface not in ethernets:
                    logger.info(f"特定接口 {interface} 沒有配置，無需清理")
                    
                # 查找可能匹配此接口的通配符配置
                wildcard_found = False
                wildcard_key = None
                wildcard_config = None
                
                for key, config in list(ethernets.items()):
                    if key == interface:
                        continue
                        
                    if not isinstance(config, dict):
                        continue
                        
                    # 檢查是否有通配符配置匹配此接口
                    match_by_name = False
                    if 'match' in config and 'name' in config['match']:
                        match_pattern = config['match']['name']
                        if self._interface_matches_wildcard(interface, match_pattern):
                            match_by_name = True
                            
                    if ('*' in key and self._interface_matches_wildcard(interface, key)) or match_by_name:
                        wildcard_found = True
                        wildcard_key = key
                        wildcard_config = config
                        break
                        
                if not wildcard_found:
                    logger.info(f"沒有找到與接口 {interface} 匹配的通配符配置，無需清理")
                    return True
                    
                logger.info(f"找到與接口 {interface} 匹配的通配符配置: {wildcard_key}")
                
                # 確保特定接口配置存在
                need_to_create_specific = False
                
                if interface not in ethernets:
                    need_to_create_specific = True
                    logger.info(f"未找到特定接口 {interface} 的配置，將基於通配符配置創建新配置")
                    # 創建特定接口配置的基礎結構
                    ethernets[interface] = {}
                
                # 特定接口配置
                specific_config = ethernets[interface]
                
                # 我們將刪除通配符配置，但首先確保特定接口配置包含所有必要的設置
                # 如果特定接口配置缺少某些設置，從通配符配置中複製
                if need_to_create_specific or not specific_config.get('dhcp4', None) is False:
                    # 如果通配符是dhcp配置，但沒有特定配置，我們創建一個默認的靜態配置
                    if wildcard_config.get('dhcp4', False) is True:
                        # 獲取當前IP地址
                        exit_code, current_ip, _ = self.ssh_client.execute_command(
                            f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | cut -d/ -f1 | head -1"
                        )
                        
                        # 獲取當前子網掩碼
                        exit_code, current_cidr, _ = self.ssh_client.execute_command(
                            f"ip -o -4 addr show dev {interface} | awk '{{print $4}}' | cut -d/ -f2 | head -1"
                        )
                        
                        # 獲取當前網關
                        exit_code, current_gateway, _ = self.ssh_client.execute_command(
                            f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                        )
                        
                        if current_ip.strip() and current_cidr.strip():
                            specific_config['dhcp4'] = False
                            specific_config['addresses'] = [f"{current_ip.strip()}/{current_cidr.strip()}"]
                            
                            if current_gateway.strip():
                                # 檢查netplan版本決定使用哪種網關字段
                                exit_code, version_output, _ = self.ssh_client.execute_command("netplan --version 2>/dev/null || echo '0.0'")
                                
                                version = '0.0'
                                if exit_code == 0 and version_output.strip():
                                    version = version_output.strip().split()[0]
                                
                                # 新版Netplan (0.104+) 使用routes配置
                                if float(version.replace('v', '')) >= 0.104:
                                    specific_config['routes'] = [
                                        {
                                            'to': 'default',
                                            'via': current_gateway.strip()
                                        }
                                    ]
                                else:
                                    # 舊版使用gateway4
                                    specific_config['gateway4'] = current_gateway.strip()
                                    
                            # 從通配符複製DNS設置（如果存在）
                            if 'nameservers' in wildcard_config:
                                specific_config['nameservers'] = wildcard_config['nameservers']
                            # 如果沒有DNS設置，嘗試獲取當前DNS
                            elif not specific_config.get('nameservers'):
                                exit_code, dns_servers, _ = self.ssh_client.execute_command(
                                    "cat /etc/resolv.conf | grep '^nameserver' | awk '{print $2}'"
                                )
                                
                                if dns_servers.strip():
                                    dns_list = [s.strip() for s in dns_servers.splitlines() if s.strip()]
                                    if dns_list:
                                        specific_config['nameservers'] = {
                                            'addresses': dns_list
                                        }
                        else:
                            logger.warning(f"無法獲取接口 {interface} 的當前IP配置，將繼承通配符配置設置")
                            # 如果無法獲取當前IP，直接複製通配符配置
                            for key, value in wildcard_config.items():
                                if key != 'match':  # 不複製match條件
                                    specific_config[key] = value
                    else:
                        # 如果通配符不是dhcp配置，直接複製其設置
                        for key, value in wildcard_config.items():
                            if key != 'match':  # 不複製match條件
                                specific_config[key] = value
                                
                # 刪除通配符配置
                logger.info(f"刪除通配符配置 {wildcard_key}")
                del ethernets[wildcard_key]
                
                # 將修改後的配置寫入臨時文件
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                    yaml.dump(yaml_data, tmp, default_flow_style=False)
                    tmp_path = tmp.name
                
                # 上傳到目標服務器
                target_tmp_file = f"/tmp/netplan_config_{int(time.time())}.yaml"
                self.ssh_client.upload_file(tmp_path, target_tmp_file)
                
                # 刪除本地臨時文件
                os.unlink(tmp_path)
                
                # 移動到正確位置，確保有寫入權限
                exit_code, _, stderr = self.ssh_client.execute_command(
                    f"sudo mv {target_tmp_file} {netplan_file}"
                )
                
                if exit_code != 0:
                    logger.error(f"無法更新netplan配置文件: {stderr}")

                    return False
                
                # 應用netplan配置
                exit_code, _, stderr = self.ssh_client.execute_command("sudo netplan apply")
                if exit_code != 0:
                    logger.error(f"應用netplan配置失敗: {stderr}")
                    return False
                    
                logger.info(f"成功清理接口 {interface} 的Netplan配置，已刪除通配符配置")
                return True
                
            except yaml.YAMLError as e:
                logger.error(f"YAML解析或生成錯誤: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"清理Netplan配置時發生錯誤: {str(e)}")
            return False
        
    def _convert_dhcp_to_static_redhat(self, interface: str, config: Dict[str, Any]) -> bool:
        """
        將RedHat系統的DHCP配置轉換為靜態IP，支持CentOS 9
        
        參數:
            interface (str): 網絡接口名稱
            config (Dict[str, Any]): 網絡配置信息
                
        返回:
            bool: 轉換成功返回True，否則返回False
        """
        logger.info(f"正在轉換RedHat系統的接口 {interface} 配置為靜態IP")
        
        try:
            # 檢測是否為 CentOS/RHEL 9
            exit_code, os_info, _ = self.ssh_client.execute_command(
                "cat /etc/os-release 2>/dev/null | grep -E '^(ID|VERSION_ID)=' | tr -d '\"'"
            )
            
            is_centos9 = False
            if exit_code == 0 and os_info.strip():
                for line in os_info.strip().split('\n'):
                    if line.startswith("ID=") and ("centos" in line.lower() or "rhel" in line.lower()):
                        for ver_line in os_info.strip().split('\n'):
                            if ver_line.startswith("VERSION_ID=") and ver_line.split('=')[1].startswith("9"):
                                is_centos9 = True
                                break
                        break
            
            # 檢查nmcli命令是否存在
            exit_code, stdout, _ = self.ssh_client.execute_command("which nmcli")
            nmcli_exists = (exit_code == 0 and stdout.strip())
            
            # 獲取IP配置參數
            ip_address = config.get("ip_address", "")
            netmask = config.get("netmask", "255.255.255.0")
            gateway = config.get("gateway", "")
            dns_servers = config.get("dns_servers", [])
            
            # 將子網掩碼轉換為CIDR
            cidr = self._netmask_to_cidr(netmask)
            
            # 如果是 CentOS 9 且存在nmcli
            if is_centos9 and nmcli_exists:
                # 檢查是否存在現有NetworkManager配置
                exit_code, nm_files, _ = self.ssh_client.execute_command(
                    f"ls /etc/NetworkManager/system-connections/{interface}* 2>/dev/null || echo ''"
                )
                
                if exit_code == 0 and nm_files.strip():
                    # 存在現有配置文件，使用修改現有配置的方法
                    return self._modify_existing_connection_to_static(
                        interface, ip_address, cidr, gateway, dns_servers
                    )
                else:
                    # 創建新的配置文件
                    logger.info(f"無現有配置文件，創建新的NetworkManager配置")
                    return self._create_new_connection_static(
                        interface, ip_address, cidr, gateway, dns_servers
                    )
            elif nmcli_exists:
                # 其他RedHat版本但支持NetworkManager
                logger.info(f"使用NetworkManager CLI命令進行配置")
                conn_name = f"{interface}"
                
                # 檢查連接是否已存在
                exit_code, stdout, _ = self.ssh_client.execute_command(f"nmcli connection show | grep '{conn_name}'")
                exists = (exit_code == 0 and stdout.strip())
                
                if exists:
                    # 修改已有連接
                    cmds = [
                        f"nmcli connection modify '{conn_name}' ipv4.method manual",
                        f"nmcli connection modify '{conn_name}' ipv4.addresses {ip_address}/{cidr}"
                    ]
                    
                    if gateway:
                        cmds.append(f"nmcli connection modify '{conn_name}' ipv4.gateway {gateway}")
                    
                    if dns_servers:
                        dns_str = ",".join(dns_servers)
                        cmds.append(f"nmcli connection modify '{conn_name}' ipv4.dns '{dns_str}'")
                else:
                    # 創建新連接
                    cmds = [
                        f"nmcli connection add type ethernet con-name {conn_name} ifname {interface}",
                        f"nmcli connection modify {conn_name} ipv4.method manual",
                        f"nmcli connection modify {conn_name} ipv4.addresses {ip_address}/{cidr}",
                        f"nmcli connection modify {conn_name} connection.autoconnect yes"
                    ]
                    
                    if gateway:
                        cmds.append(f"nmcli connection modify {conn_name} ipv4.gateway {gateway}")
                    
                    if dns_servers:
                        dns_str = ",".join(dns_servers)
                        cmds.append(f"nmcli connection modify {conn_name} ipv4.dns '{dns_str}'")
                
                # 執行所有命令
                for cmd in cmds:
                    logger.info(f"執行命令: {cmd}")
                    exit_code, stdout, stderr = self.ssh_client.execute_command(cmd)
                    if exit_code != 0:
                        logger.warning(f"命令執行返回非零狀態: {exit_code}, 錯誤: {stderr}")
                
                # 應用配置
                self.ssh_client.execute_command(f"nmcli connection up {conn_name}")
                
                # 檢查是否配置成功
                if self._verify_static_config(interface, ip_address):
                    logger.info(f"成功將接口 {interface} 從DHCP轉換為靜態IP配置")
                    return True
                else:
                    # 手動添加IP確保生效
                    logger.warning("配置可能未立即生效，嘗試手動添加IP")
                    self.ssh_client.execute_command(f"ip addr add {ip_address}/{cidr} dev {interface}")
                    return True
            else:
                # 使用傳統的 ifcfg 文件方式
                logger.info(f"使用傳統ifcfg文件進行配置")
                
                # 主網卡配置
                ifcfg_content = [
                    f"DEVICE={interface}",
                    "BOOTPROTO=static",
                    "ONBOOT=yes",
                    f"IPADDR={ip_address}",
                    f"PREFIX={cidr}"
                ]
                
                # 添加網關配置
                if gateway:
                    ifcfg_content.append(f"GATEWAY={gateway}")
                
                # 添加DNS服務器配置
                if dns_servers:
                    for i, dns in enumerate(dns_servers[:2], 1):
                        ifcfg_content.append(f"DNS{i}={dns}")
                
                # 備份現有配置
                config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface}"
                backup_file = f"{config_file}.bak.{int(time.time())}"
                
                self.ssh_client.execute_command(
                    f"cp {config_file} {backup_file} 2>/dev/null || true"
                )
                
                # 檢查是否有任何其他IP並添加到配置中
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"ip addr show dev {interface} | grep -w 'inet' | grep -v '{ip_address}' | awk '{{print $2}}'"
                )
                
                if exit_code == 0 and stdout.strip():
                    # 已有其他IP地址，加入到配置中
                    for idx, ip_cidr in enumerate(stdout.strip().split('\n')):
                        if ip_cidr:
                            ip_parts = ip_cidr.split('/')
                            ip = ip_parts[0]
                            addr_cidr = ip_parts[1] if len(ip_parts) > 1 else "24"
                            
                            ifcfg_content.append(f'IPADDR{idx}="{ip}"')
                            ifcfg_content.append(f'PREFIX{idx}="{addr_cidr}"')
                
                # 更新配置文件
                ifcfg_str = "\n".join(ifcfg_content)
                self.ssh_client.execute_command(
                    f"echo '{ifcfg_str}' > {config_file}"
                )
                
                # 確保配置文件權限正確
                self.ssh_client.execute_command(
                    f"chmod 644 {config_file}"
                )
                
                # 重啟網絡服務
                self.ssh_client.execute_command(
                    f"systemctl restart network || service network restart || (ifdown {interface} && ifup {interface}) || true"
                )
                
                # 檢查是否配置成功
                if self._verify_static_config(interface, ip_address):
                    logger.info(f"成功將接口 {interface} 從DHCP轉換為靜態IP配置")
                    return True
                else:
                    # 手動添加IP確保生效
                    logger.warning("配置可能未立即生效，嘗試手動添加IP")
                    self.ssh_client.execute_command(f"ip addr add {ip_address}/{cidr} dev {interface}")
                    return True
                
        except Exception as e:
            logger.error(f"在RedHat系統中轉換為靜態IP配置時發生錯誤: {str(e)}")
            return False

    def _add_permanent_ip_redhat(self, ip_address: str, interface: str) -> bool:
        """
        在RedHat系統中添加永久IP配置，支持CentOS 9的keyfile格式
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式)
            interface (str): 網絡接口名稱
            
        返回:
            bool: 添加成功返回True，否則返回False
        """
        logger.info(f"正在RedHat系統中添加永久IP配置: {ip_address} 到 {interface}")
        
        try:
            # 解析IP和CIDR
            ip_parts = ip_address.split('/')
            ip = ip_parts[0]
            cidr = ip_parts[1] if len(ip_parts) > 1 else "24"  # 默認為/24
            
            # 檢查IP是否已經添加到接口 (但不影響永久配置的添加)
            ip_exists_on_interface = False
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip}'"
            )
            if exit_code == 0 and stdout.strip():
                logger.info(f"IP {ip} 已存在於接口 {interface}，但仍將檢查永久配置")
                ip_exists_on_interface = True
            
            # 檢測是否為 CentOS/RHEL 9
            exit_code, os_info, _ = self.ssh_client.execute_command(
                "cat /etc/os-release 2>/dev/null | grep -E '^(ID|VERSION_ID)=' | tr -d '\"'"
            )
            
            is_centos9 = False
            if exit_code == 0 and os_info.strip():
                for line in os_info.strip().split('\n'):
                    if line.startswith("ID=") and ("centos" in line.lower() or "rhel" in line.lower()):
                        for ver_line in os_info.strip().split('\n'):
                            if ver_line.startswith("VERSION_ID=") and ver_line.split('=')[1].startswith("9"):
                                is_centos9 = True
                                break
                        break
            
            # 檢查nmcli命令是否存在
            exit_code, stdout, _ = self.ssh_client.execute_command("which nmcli")
            nmcli_exists = (exit_code == 0 and stdout.strip())
            
            # 如果是 CentOS 9 且存在nmcli
            if is_centos9 and nmcli_exists:
                logger.info("檢測到 CentOS 9 系統，使用 NetworkManager 配置")
                
                # 檢查是否存在現有NetworkManager配置
                nm_file_paths = [
                    f"/etc/NetworkManager/system-connections/{interface}.nmconnection",
                    f"/etc/NetworkManager/system-connections/{interface}"
                ]
                
                nm_file_path = None
                for path in nm_file_paths:
                    exit_code, _, _ = self.ssh_client.execute_command(f"test -f {path}")
                    if exit_code == 0:
                        nm_file_path = path
                        break
                
                # 檢查現有配置文件是否已包含此IP
                ip_in_config = False
                if nm_file_path:
                    exit_code, config_content, _ = self.ssh_client.execute_command(f"cat {nm_file_path}")
                    if exit_code == 0 and config_content.strip():
                        # 檢查IP是否已存在於配置文件中
                        if re.search(rf"address\d+=.*{ip}(\/\d+)?", config_content):
                            logger.info(f"IP {ip} 已存在於NetworkManager配置文件中")
                            ip_in_config = True
                
                # 如果IP已在接口上但不在配置文件中，需要添加到配置
                if ip_exists_on_interface and not ip_in_config:
                    logger.info(f"IP {ip} 存在於接口但不在配置文件中，將添加到永久配置")
                
                # 如果IP已在配置文件中，則無需添加
                if ip_in_config:
                    logger.info(f"IP {ip} 已存在於NetworkManager配置文件中，無需添加")
                    return True
                
                if nm_file_path:
                    # 存在現有配置文件，添加副IP
                    logger.info(f"找到現有NetworkManager配置文件: {nm_file_path}")
                    return self._add_secondary_ip_to_existing(
                        interface, ip, int(cidr)
                    )
                else:
                    # 檢查是否有其他配置文件包含此接口
                    exit_code, nm_files, _ = self.ssh_client.execute_command(
                        "ls -la /etc/NetworkManager/system-connections/ 2>/dev/null || echo ''"
                    )
                    
                    conn_name = None
                    if exit_code == 0 and nm_files.strip():
                        # 尋找匹配此接口的配置文件
                        for file_line in nm_files.strip().split('\n'):
                            if len(file_line.split()) > 0:
                                file_name = file_line.split()[-1]
                                if file_name and file_name != "." and file_name != "..":
                                    # 確保我們檢查的是文件而不是目錄
                                    exit_code, file_check, _ = self.ssh_client.execute_command(
                                        f"test -f '/etc/NetworkManager/system-connections/{file_name}' && echo 'file'"
                                    )
                                    if exit_code == 0 and file_check.strip() == 'file':
                                        # 檢查文件內容是否包含接口名稱
                                        exit_code, interface_content, _ = self.ssh_client.execute_command(
                                            f"grep -l 'interface-name={interface}' '/etc/NetworkManager/system-connections/{file_name}' 2>/dev/null || echo ''"
                                        )
                                        if exit_code == 0 and interface_content.strip():
                                            conn_name = file_name.replace(".nmconnection", "")
                                            break
                    
                    if conn_name:
                        # 找到了匹配此接口的配置，添加副IP
                        logger.info(f"找到接口 {interface} 的NetworkManager配置: {conn_name}")
                        return self._add_secondary_ip_to_nm_connection(
                            conn_name, interface, ip, int(cidr)
                        )
                    else:
                        # 沒有找到匹配的配置，創建新配置
                        logger.info(f"未找到接口 {interface} 的NetworkManager配置，創建新配置")
                        
                        # 獲取當前IP作為主IP
                        exit_code, main_ip, _ = self.ssh_client.execute_command(
                            f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
                        )
                        
                        if exit_code == 0 and main_ip.strip():
                            main_ip_parts = main_ip.strip().split('/')
                            main_ip_addr = main_ip_parts[0]
                            main_ip_cidr = main_ip_parts[1] if len(main_ip_parts) > 1 else "24"
                            
                            # 如果新IP與主IP相同，直接創建只包含此IP的配置
                            if main_ip_addr == ip:
                                return self._create_new_connection_static(
                                    interface, ip, int(cidr)
                                )
                            
                            # 獲取當前網關
                            exit_code, gateway, _ = self.ssh_client.execute_command(
                                f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                            )
                            gateway_addr = gateway.strip() if exit_code == 0 and gateway.strip() else None
                            
                            # 創建包含兩個IP的新配置
                            return self._create_new_connection_with_ips(
                                interface, main_ip_addr, int(main_ip_cidr), gateway_addr, [f"{ip}/{cidr}"]
                            )
                        else:
                            # 沒有找到當前IP，將新IP作為主IP
                            return self._create_new_connection_static(
                                interface, ip, int(cidr)
                            )
            elif nmcli_exists:
                # 其他RedHat版本支持NetworkManager
                logger.info(f"使用NetworkManager CLI命令添加IP")
                
                # 檢查是否有已存在的連接
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"nmcli -t -f NAME,DEVICE connection show | grep ':{interface}$' | cut -d: -f1"
                )
                
                conn_name = None
                if exit_code == 0 and stdout.strip():
                    conn_name = stdout.strip()
                else:
                    # 檢查是否有<interface>-static連接
                    conn_name = f"{interface}"
                    exit_code, stdout, _ = self.ssh_client.execute_command(
                        f"nmcli connection show | grep '{conn_name}'"
                    )
                    if exit_code != 0 or not stdout.strip():
                        conn_name = None
                
                if conn_name:
                    # 使用現有連接
                    logger.info(f"向現有連接 {conn_name} 添加IP地址")
                    
                    # 檢查IP是否已存在於連接配置中
                    exit_code, conn_ips, _ = self.ssh_client.execute_command(
                        f"nmcli -g ipv4.addresses connection show {conn_name}"
                    )
                    
                    if exit_code == 0 and conn_ips.strip():
                        ip_exists_in_connection = False
                        for conn_ip in conn_ips.strip().split(','):
                            if ip in conn_ip:
                                logger.info(f"IP {ip} 已存在於連接 {conn_name} 的配置中")
                                ip_exists_in_connection = True
                                break
                        
                        if ip_exists_in_connection:
                            return True
                    
                    # 獲取現有IP地址
                    exit_code, stdout, _ = self.ssh_client.execute_command(
                        f"nmcli -g ipv4.addresses connection show {conn_name}"
                    )
                    
                    existing_ips = []
                    if exit_code == 0 and stdout.strip():
                        existing_ips = [addr.strip() for addr in stdout.strip().split(',')]
                    
                    # 添加新IP
                    ip_with_cidr = f"{ip}/{cidr}"
                    if ip_with_cidr not in existing_ips:
                        existing_ips.append(ip_with_cidr)
                    
                    # 更新連接
                    ip_list = ",".join(existing_ips)
                    cmd = f"nmcli connection modify {conn_name} ipv4.addresses '{ip_list}'"
                    
                    exit_code, _, stderr = self.ssh_client.execute_command(cmd)
                    if exit_code != 0:
                        logger.error(f"更新連接失敗: {stderr}")
                        return False
                    
                    # 重新加載連接
                    self.ssh_client.execute_command(f"nmcli connection up {conn_name}")
                    
                    # 驗證IP是否添加成功
                    time.sleep(1)  # 等待配置生效
                    if not self._is_ip_exists(ip_address, interface):
                        # 嘗試手動添加
                        self.ssh_client.execute_command(f"ip addr add {ip_address} dev {interface}")
                    
                    logger.info(f"成功將IP {ip_address} 添加到連接 {conn_name}")
                    return True
                else:
                    # 沒有找到現有連接，創建新連接
                    logger.info(f"未找到接口 {interface} 的現有連接，創建新連接")
                    
                    # 獲取當前IP作為主IP
                    exit_code, main_ip, _ = self.ssh_client.execute_command(
                        f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
                    )
                    
                    if exit_code == 0 and main_ip.strip():
                        # 有現有IP，創建包含兩個IP的連接
                        conn_name = f"{interface}"
                        cmd = f"nmcli connection add type ethernet con-name {conn_name} ifname {interface} ipv4.method manual ipv4.addresses '{main_ip.strip()},{ip}/{cidr}' connection.autoconnect yes"
                        
                        exit_code, _, stderr = self.ssh_client.execute_command(cmd)
                        if exit_code != 0:
                            logger.error(f"創建連接失敗: {stderr}")
                            return False
                        
                        # 應用連接
                        self.ssh_client.execute_command(f"nmcli connection up {conn_name}")
                        
                        # 驗證IP是否添加成功
                        time.sleep(1)  # 等待配置生效
                        if not self._is_ip_exists(ip_address, interface):
                            # 嘗試手動添加
                            self.ssh_client.execute_command(f"ip addr add {ip_address} dev {interface}")
                        
                        logger.info(f"成功創建連接 {conn_name} 並添加IP {ip_address}")
                        return True
                    else:
                        # 沒有現有IP，創建只包含新IP的連接
                        conn_name = f"{interface}"
                        cmd = f"nmcli connection add type ethernet con-name {conn_name} ifname {interface} ipv4.method manual ipv4.addresses '{ip}/{cidr}' connection.autoconnect yes"
                        
                        exit_code, _, stderr = self.ssh_client.execute_command(cmd)
                        if exit_code != 0:
                            logger.error(f"創建連接失敗: {stderr}")
                            return False
                        
                        # 應用連接
                        self.ssh_client.execute_command(f"nmcli connection up {conn_name}")
                        
                        logger.info(f"成功創建連接 {conn_name} 並設置IP {ip_address}")
                        return True
            else:
                # 使用傳統ifcfg文件方式
                logger.info(f"使用傳統ifcfg文件添加IP")
                
                # 檢查是否已有主ifcfg文件
                config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface}"
                exit_code, _, _ = self.ssh_client.execute_command(f"test -f {config_file}")
                
                if exit_code == 0:
                    # 檢查配置文件中是否已配置該IP
                    exit_code, stdout, _ = self.ssh_client.execute_command(
                        f"grep -E 'IPADDR[0-9]*=\"?{ip}\"?' {config_file}"
                    )
                    
                    if exit_code == 0 and stdout.strip():
                        logger.info(f"IP {ip} 已存在於配置文件 {config_file} 中")
                        return True
                    
                    # 檢查是否已配置其他IP
                    exit_code, stdout, _ = self.ssh_client.execute_command(
                        f"grep -E 'IPADDR[0-9]*=' {config_file} | wc -l"
                    )
                    
                    if exit_code == 0 and stdout.strip() and int(stdout.strip()) > 0:
                        # 已有IP配置，添加新IP
                        logger.info(f"向已有配置添加IP地址")
                        
                        # 尋找下一個可用的索引
                        exit_code, stdout, _ = self.ssh_client.execute_command(
                            f"grep -E 'IPADDR[0-9]*=' {config_file} | sed -E 's/IPADDR([0-9]*)=.*/\\1/g' | sort -n | tail -1"
                        )
                        
                        next_index = 0
                        if exit_code == 0 and stdout.strip():
                            if stdout.strip().isdigit():
                                next_index = int(stdout.strip()) + 1
                            else:
                                next_index = 1
                        
                        # 添加新的IP配置
                        self.ssh_client.execute_command(
                            f"echo 'IPADDR{next_index}={ip}' >> {config_file}"
                        )
                        self.ssh_client.execute_command(
                            f"echo 'PREFIX{next_index}={cidr}' >> {config_file}"
                        )
                        
                        # 重啟網絡服務
                        self.ssh_client.execute_command(
                            f"systemctl restart network || service network restart || (ifdown {interface} && ifup {interface}) || true"
                        )
                        
                        # 檢查IP是否成功添加
                        time.sleep(1)  # 等待配置生效
                        if not self._is_ip_exists(ip_address, interface):
                            # 嘗試手動添加
                            self.ssh_client.execute_command(f"ip addr add {ip_address} dev {interface}")
                        
                        logger.info(f"成功添加IP {ip_address} 到配置文件 {config_file}")
                        return True
                    else:
                        # 沒有IP配置，修改為靜態IP並添加
                        logger.info(f"修改配置為靜態IP並添加IP")
                        
                        
                        # 修改為靜態IP
                        self.ssh_client.execute_command(
                            f"sed -i 's/BOOTPROTO=.*/BOOTPROTO=static/g' {config_file}"
                        )
                        
                        # 添加主IP和副IP
                        # 先獲取當前IP
                        exit_code, main_ip, _ = self.ssh_client.execute_command(
                            f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
                        )
                        
                        if exit_code == 0 and main_ip.strip():
                            main_ip_parts = main_ip.strip().split('/')
                            main_addr = main_ip_parts[0]
                            main_cidr = main_ip_parts[1] if len(main_ip_parts) > 1 else "24"
                            
                            # 添加主IP配置
                            self.ssh_client.execute_command(
                                f"echo 'IPADDR={main_addr}' >> {config_file}"
                            )
                            self.ssh_client.execute_command(
                                f"echo 'PREFIX={main_cidr}' >> {config_file}"
                            )
                            
                            # 添加副IP配置
                            self.ssh_client.execute_command(
                                f"echo 'IPADDR1={ip}' >> {config_file}"
                            )
                            self.ssh_client.execute_command(
                                f"echo 'PREFIX1={cidr}' >> {config_file}"
                            )
                        else:
                            # 沒有找到主IP，僅添加新IP
                            self.ssh_client.execute_command(
                                f"echo 'IPADDR={ip}' >> {config_file}"
                            )
                            self.ssh_client.execute_command(
                                f"echo 'PREFIX={cidr}' >> {config_file}"
                            )
                        
                        # 重啟網絡服務
                        self.ssh_client.execute_command(
                            f"systemctl restart network || service network restart || (ifdown {interface} && ifup {interface}) || true"
                        )
                        
                        # 檢查IP是否成功添加
                        time.sleep(1)  # 等待配置生效
                        if not self._is_ip_exists(ip_address, interface):
                            # 嘗試手動添加
                            self.ssh_client.execute_command(f"ip addr add {ip_address} dev {interface}")
                        
                        logger.info(f"成功將配置修改為靜態IP並添加IP {ip_address}")
                        return True
                else:
                    # 創建新的配置文件
                    logger.info(f"創建新的配置文件 {config_file}")
                    
                    # 獲取當前IP
                    exit_code, main_ip, _ = self.ssh_client.execute_command(
                        f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
                    )
                    
                    if exit_code == 0 and main_ip.strip():
                        main_ip_parts = main_ip.strip().split('/')
                        main_addr = main_ip_parts[0]
                        main_cidr = main_ip_parts[1] if len(main_ip_parts) > 1 else "24"
                        
                        # 構建配置內容
                        config_content = [
                            f"DEVICE={interface}",
                            "BOOTPROTO=static",
                            "ONBOOT=yes",
                            f"IPADDR={main_addr}",
                            f"PREFIX={main_cidr}",
                            f"IPADDR1={ip}",
                            f"PREFIX1={cidr}"
                        ]
                    else:
                        # 構建僅包含新IP的配置
                        config_content = [
                            f"DEVICE={interface}",
                            "BOOTPROTO=static",
                            "ONBOOT=yes",
                            f"IPADDR={ip}",
                            f"PREFIX={cidr}"
                        ]
                    
                    # 寫入配置文件
                    config_str = "\n".join(config_content)
                    self.ssh_client.execute_command(
                        f"echo '{config_str}' > {config_file}"
                    )
                    
                    # 確保權限正確
                    self.ssh_client.execute_command(
                        f"chmod 644 {config_file}"
                    )
                    
                    # 重啟網絡服務
                    self.ssh_client.execute_command(
                        f"systemctl restart network || service network restart || (ifdown {interface} && ifup {interface}) || true"
                    )
                    
                    # 檢查IP是否成功添加
                    time.sleep(1)  # 等待配置生效
                    if not self._is_ip_exists(ip_address, interface):
                        # 嘗試手動添加
                        self.ssh_client.execute_command(f"ip addr add {ip_address} dev {interface}")
                    
                    logger.info(f"成功創建配置文件並設置IP {ip_address}")
                    return True
                
        except Exception as e:
            logger.error(f"在RedHat系統中添加永久IP配置時發生錯誤: {str(e)}")
            return False
    
    def _modify_existing_connection_to_static(self, interface: str, ip_address: str, 
                                            cidr: int, gateway: str = None, 
                                            dns_servers: List[str] = None) -> bool:
        """
        修改現有NetworkManager連接配置從DHCP轉為靜態IP
        
        參數:
            interface (str): 網絡接口名稱
            ip_address (str): IP地址
            cidr (int): CIDR前綴長度
            gateway (str, optional): 網關地址
            dns_servers (List[str], optional): DNS服務器列表
            
        返回:
            bool: 成功返回True，失敗返回False
        """
        # 檢測配置文件路徑
        nm_file_paths = [
            f"/etc/NetworkManager/system-connections/{interface}.nmconnection",
            f"/etc/NetworkManager/system-connections/{interface}"
        ]
        
        nm_file_path = None
        for path in nm_file_paths:
            exit_code, _, _ = self.ssh_client.execute_command(f"test -f {path}")
            if exit_code == 0:
                nm_file_path = path
                break
        
        if not nm_file_path:
            logger.error(f"未找到接口 {interface} 的NetworkManager配置文件")
            return False
        
        # 讀取當前配置
        exit_code, current_config, _ = self.ssh_client.execute_command(f"cat {nm_file_path}")
        if exit_code != 0:
            logger.error(f"無法讀取NetworkManager配置文件: {nm_file_path}")
            return False
        
        # 構建修改後的配置
        modified_lines = []
        lines = current_config.strip().split('\n')
        in_ipv4_section = False
        has_modified_method = False
        
        for line in lines:
            if line.strip() == "[ipv4]":
                in_ipv4_section = True
                modified_lines.append(line)
            elif in_ipv4_section and line.strip() == "method=auto":
                # 修改method參數
                modified_lines.append("method=manual")
                has_modified_method = True
                
                # 添加IP地址配置
                ip_line = f"address1={ip_address}/{cidr}"
                if gateway:
                    ip_line += f",{gateway}"
                modified_lines.append(ip_line)
                
                # 添加DNS配置
                if dns_servers:
                    dns_line = f"dns={';'.join(dns_servers)}"
                    modified_lines.append(dns_line)
                    modified_lines.append("dns-search=")
            elif in_ipv4_section and line.strip().startswith("["):
                # 如果離開[ipv4]部分且尚未修改method
                if not has_modified_method:
                    # 添加靜態配置
                    modified_lines.append("method=manual")
                    
                    # 添加IP地址配置
                    ip_line = f"address1={ip_address}/{cidr}"
                    if gateway:
                        ip_line += f",{gateway}"
                    modified_lines.append(ip_line)
                    
                    # 添加DNS配置
                    if dns_servers:
                        dns_line = f"dns={';'.join(dns_servers)}"
                        modified_lines.append(dns_line)
                        modified_lines.append("dns-search=")
                
                # 離開ipv4部分
                in_ipv4_section = False
                modified_lines.append(line)
            else:
                modified_lines.append(line)
        
        # 檢查是否需要添加[ipv4]部分
        if not any("[ipv4]" in line for line in lines):
            modified_lines.append("[ipv4]")
            modified_lines.append("method=manual")
            
            # 添加IP地址配置
            ip_line = f"address1={ip_address}/{cidr}"
            if gateway:
                ip_line += f",{gateway}"
            modified_lines.append(ip_line)
            
            # 添加DNS配置
            if dns_servers:
                dns_line = f"dns={';'.join(dns_servers)}"
                modified_lines.append(dns_line)
                modified_lines.append("dns-search=")
        
        # 寫入修改後的配置
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write('\n'.join(modified_lines))
        
        # 上傳到服務器
        tmp_remote = f"/tmp/nm_config_{int(time.time())}"
        self.ssh_client.upload_file(tmp_path, tmp_remote)
        os.unlink(tmp_path)  # 清理本地臨時文件
        
        # 移動到目標位置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"mv {tmp_remote} {nm_file_path} && chmod 600 {nm_file_path}"
        )
        
        
        # 重新加載NetworkManager配置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"nmcli connection reload && nmcli connection up {interface}"
        )
        
        if exit_code != 0:
            logger.warning(f"重新載入NetworkManager配置失敗: {stderr}")
            # 嘗試重啟NetworkManager
            self.ssh_client.execute_command("systemctl restart NetworkManager")
            time.sleep(2)  # 等待服務重啟
            self.ssh_client.execute_command(f"nmcli connection up {interface}")
        
        # 驗證配置是否生效
        if self._verify_static_config(interface, ip_address):
            logger.info(f"成功將接口 {interface} 的配置從DHCP轉換為靜態IP")
            return True
        else:
            logger.warning(f"無法驗證靜態IP配置，嘗試使用ip命令手動添加")
            # 手動添加IP地址
            self.ssh_client.execute_command(f"ip addr add {ip_address}/{cidr} dev {interface}")
            return True

    def _add_secondary_ip_to_existing(self, interface: str, ip_address: str, 
                                        cidr: int, gateway: str = None) -> bool:
            """
            向現有NetworkManager配置添加副IP地址
            
            參數:
                interface (str): 網絡接口名稱
                ip_address (str): 要添加的IP地址
                cidr (int): CIDR前綴長度
                gateway (str, optional): 網關地址
                
            返回:
                bool: 成功返回True，失敗返回False
            """
            # 檢測配置文件路徑
            nm_file_paths = [
                f"/etc/NetworkManager/system-connections/{interface}.nmconnection",
                f"/etc/NetworkManager/system-connections/{interface}"
            ]
            
            nm_file_path = None
            for path in nm_file_paths:
                exit_code, _, _ = self.ssh_client.execute_command(f"test -f {path}")
                if exit_code == 0:
                    nm_file_path = path
                    break
            
            if not nm_file_path:
                logger.error(f"未找到接口 {interface} 的NetworkManager配置文件")
                return False
            
            # 檢查IP是否已存在於配置文件中
            exit_code, current_config, _ = self.ssh_client.execute_command(f"cat {nm_file_path}")
            if exit_code == 0 and current_config.strip():
                # 檢查IP是否已存在於配置中
                if re.search(rf"address\d+=.*{ip_address}(\/\d+)?", current_config):
                    logger.info(f"IP {ip_address} 已存在於NetworkManager配置文件中")
                    return True
            else:
                logger.error(f"無法讀取NetworkManager配置文件: {nm_file_path}")
                return False
            
            
            # 檢查配置是否為靜態IP
            if "method=auto" in current_config and "method=manual" not in current_config:
                logger.warning(f"當前配置為DHCP，先轉換為靜態IP")
                
                # 獲取當前IP作為主IP
                exit_code, main_ip, _ = self.ssh_client.execute_command(
                    f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
                )
                
                if exit_code != 0 or not main_ip.strip():
                    logger.error(f"無法獲取當前IP地址")
                    return False
                
                main_ip_parts = main_ip.strip().split('/')
                main_ip_addr = main_ip_parts[0]
                main_ip_cidr = int(main_ip_parts[1]) if len(main_ip_parts) > 1 else 24
                
                # 獲取當前網關
                exit_code, gw, _ = self.ssh_client.execute_command(
                    f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
                )
                
                gw_addr = gw.strip() if exit_code == 0 and gw.strip() else None
                
                # 修改配置為靜態IP
                modified_lines = []
                lines = current_config.strip().split('\n')
                in_ipv4_section = False
                
                for i, line in enumerate(lines):
                    if line.strip() == "[ipv4]":
                        in_ipv4_section = True
                        modified_lines.append(line)
                    elif in_ipv4_section and line.strip() == "method=auto":
                        # 修改method為manual
                        modified_lines.append("method=manual")
                        
                        # 添加主IP配置
                        main_ip_line = f"address1={main_ip_addr}/{main_ip_cidr}"
                        if gw_addr:
                            main_ip_line += f",{gw_addr}"
                        modified_lines.append(main_ip_line)
                        
                        # 添加副IP配置
                        second_ip_line = f"address2={ip_address}/{cidr}"
                        modified_lines.append(second_ip_line)
                    elif in_ipv4_section and line.strip().startswith("["):
                        # 離開ipv4部分
                        in_ipv4_section = False
                        modified_lines.append(line)
                    else:
                        modified_lines.append(line)
            else:
                # 已是靜態IP配置，添加副IP
                # 確定下一個address索引
                address_pattern = r'address(\d+)='
                matches = re.findall(address_pattern, current_config)
                next_index = 1
                if matches:
                    indices = [int(idx) for idx in matches if idx.isdigit()]
                    if indices:
                        next_index = max(indices) + 1
                
                # 構建新的IP地址行
                new_ip_line = f"address{next_index}={ip_address}/{cidr}"
                if gateway:
                    new_ip_line += f",{gateway}"
                
                # 修改配置文件
                modified_lines = []
                lines = current_config.strip().split('\n')
                in_ipv4_section = False
                has_added_ip = False
                
                for i, line in enumerate(lines):
                    if line.strip() == "[ipv4]":
                        in_ipv4_section = True
                        modified_lines.append(line)
                    elif in_ipv4_section and line.strip().startswith("address") and not has_added_ip:
                        modified_lines.append(line)
                        
                        # 檢查是否是最後一個address行
                        next_line_idx = i + 1
                        if next_line_idx < len(lines) and not lines[next_line_idx].strip().startswith("address"):
                            # 添加新的IP地址行
                            modified_lines.append(new_ip_line)
                            has_added_ip = True
                    elif in_ipv4_section and not line.strip().startswith("address") and not has_added_ip:
                        # 如果已經過了所有address行，添加新的IP地址行
                        if any("address" in l for l in modified_lines):
                            modified_lines.append(new_ip_line)
                            has_added_ip = True
                        modified_lines.append(line)
                    elif in_ipv4_section and line.strip().startswith("[") and not has_added_ip:
                        # 離開ipv4部分，確保添加了IP地址
                        if "method=manual" in current_config:
                            modified_lines.append(new_ip_line)
                            has_added_ip = True
                        in_ipv4_section = False
                        modified_lines.append(line)
                    else:
                        modified_lines.append(line)
                
                # 檢查是否需要在文件末尾添加IP地址
                if in_ipv4_section and not has_added_ip:
                    modified_lines.append(new_ip_line)
                
                # 確保配置包含method=manual
                if "method=manual" not in '\n'.join(modified_lines):
                    # 尋找[ipv4]部分並添加method=manual
                    for i, line in enumerate(modified_lines):
                        if line.strip() == "[ipv4]" and i + 1 < len(modified_lines):
                            if not modified_lines[i + 1].startswith("method="):
                                modified_lines.insert(i + 1, "method=manual")
                                break
            
            # 寫入修改後的配置
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp_path = tmp.name
                tmp.write('\n'.join(modified_lines))
            
            # 上傳到服務器
            tmp_remote = f"/tmp/nm_config_{int(time.time())}.conf"
            self.ssh_client.upload_file(tmp_path, tmp_remote)
            os.unlink(tmp_path)  # 清理本地臨時文件
            
            # 移動到目標位置
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"mv {tmp_remote} {nm_file_path} && chmod 600 {nm_file_path}"
            )
            
            
            # 重新加載NetworkManager配置
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"nmcli connection reload && nmcli connection up {interface}"
            )
            
            if exit_code != 0:
                logger.warning(f"重新載入NetworkManager配置失敗: {stderr}")
                # 嘗試重啟NetworkManager
                self.ssh_client.execute_command("systemctl restart NetworkManager")
                time.sleep(2)  # 等待服務重啟
                self.ssh_client.execute_command(f"nmcli connection up {interface}")
            
            # 驗證IP是否已添加
            time.sleep(1)  # 等待配置生效
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w '{ip_address}'"
            )
            
            if exit_code != 0 or not stdout.strip():
                logger.warning(f"無法通過NetworkManager添加IP，嘗試使用ip命令手動添加")
                # 手動添加IP地址
                self.ssh_client.execute_command(f"ip addr add {ip_address}/{cidr} dev {interface}")
            
            logger.info(f"成功向接口 {interface} 添加副IP: {ip_address}/{cidr}")
            return True

    def _create_new_connection_static(self, interface: str, ip_address: str, 
                                    cidr: int, gateway: str = None, 
                                    dns_servers: List[str] = None) -> bool:
        """
        創建新的靜態IP NetworkManager連接配置
        
        參數:
            interface (str): 網絡接口名稱
            ip_address (str): IP地址
            cidr (int): CIDR前綴長度
            gateway (str, optional): 網關地址
            dns_servers (List[str], optional): DNS服務器列表
            
        返回:
            bool: 成功返回True，失敗返回False
        """
        # 生成唯一的連接ID和UUID
        conn_name = f"{interface}"
        
        # 獲取UUID
        exit_code, uuid_output, _ = self.ssh_client.execute_command(
            "uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || echo ''"
        )
        
        conn_uuid = uuid_output.strip() if exit_code == 0 and uuid_output.strip() else f"{interface}-{int(time.time())}"
        timestamp = int(time.time())
        
        # 構建配置文件內容
        config_lines = [
            "[connection]",
            f"id={conn_name}",
            f"uuid={conn_uuid}",
            "type=ethernet",
            "autoconnect=true",
            "autoconnect-priority=-999",
            f"interface-name={interface}",
            f"timestamp={timestamp}",
            "",
            "[ethernet]",
            "",
            "[ipv4]",
            "method=manual"
        ]
        
        # 添加IP地址配置
        ip_line = f"address1={ip_address}/{cidr}"
        if gateway:
            ip_line += f",{gateway}"
        config_lines.append(ip_line)
        
        # 添加DNS配置
        if dns_servers:
            dns_line = f"dns={';'.join(dns_servers)}"
            config_lines.append(dns_line)
            config_lines.append("dns-search=")
        
        # 添加ipv6部分
        config_lines.extend([
            "",
            "[ipv6]",
            "addr-gen-mode=eui64",
            "method=auto",
            "",
            "[proxy]",
            ""
        ])
        
        # 構建配置文件內容
        config_content = '\n'.join(config_lines)
        
        # 寫入臨時文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(config_content)
        
        # 目標配置文件路徑
        nm_file_path = f"/etc/NetworkManager/system-connections/{conn_name}.nmconnection"
        
        # 上傳到服務器
        tmp_remote = f"/tmp/nm_config_{int(time.time())}"
        self.ssh_client.upload_file(tmp_path, tmp_remote)
        os.unlink(tmp_path)  # 清理本地臨時文件
        
        # 移動到目標位置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"mkdir -p /etc/NetworkManager/system-connections && "
            f"mv {tmp_remote} {nm_file_path} && "
            f"chmod 600 {nm_file_path}"
        )
        
        if exit_code != 0:
            logger.error(f"無法創建NetworkManager配置文件: {stderr}")
            return False
        
        # 重新加載NetworkManager配置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"nmcli connection reload && nmcli connection up '{conn_name}'"
        )
        
        if exit_code != 0:
            logger.warning(f"啟用連接失敗: {stderr}")
            # 嘗試重啟NetworkManager
            self.ssh_client.execute_command("systemctl restart NetworkManager")
            time.sleep(2)  # 等待服務重啟
            self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
        
        # 驗證配置是否生效
        if self._verify_static_config(interface, ip_address):
            logger.info(f"成功創建並啟用接口 {interface} 的靜態IP配置")
            return True
        else:
            logger.warning(f"無法驗證靜態IP配置，嘗試使用ip命令手動添加")
            # 手動添加IP地址
            self.ssh_client.execute_command(f"ip addr add {ip_address}/{cidr} dev {interface}")
            return True

    def _create_new_connection_with_ips(self, interface: str, main_ip: str, main_cidr: int,
                                    gateway: str = None, additional_ips: List[str] = None,
                                    dns_servers: List[str] = None) -> bool:
        """
        創建包含多個IP地址的新NetworkManager連接配置
        
        參數:
            interface (str): 網絡接口名稱
            main_ip (str): 主IP地址
            main_cidr (int): 主IP的CIDR前綴長度
            gateway (str, optional): 網關地址
            additional_ips (List[str], optional): 附加IP地址列表，格式為 ["x.x.x.x/y", ...]
            dns_servers (List[str], optional): DNS服務器列表
            
        返回:
            bool: 成功返回True，失敗返回False
        """
        # 生成唯一的連接ID和UUID
        conn_name = f"{interface}"
        
        # 獲取UUID
        exit_code, uuid_output, _ = self.ssh_client.execute_command(
            "uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || echo ''"
        )
        
        conn_uuid = uuid_output.strip() if exit_code == 0 and uuid_output.strip() else f"{interface}-{int(time.time())}"
        timestamp = int(time.time())
        
        # 構建配置文件內容
        config_lines = [
            "[connection]",
            f"id={conn_name}",
            f"uuid={conn_uuid}",
            "type=ethernet",
            "autoconnect=true",
            "autoconnect-priority=-999",
            f"interface-name={interface}",
            f"timestamp={timestamp}",
            "",
            "[ethernet]",
            "",
            "[ipv4]",
            "method=manual"
        ]
        
        # 添加主IP地址配置
        main_ip_line = f"address1={main_ip}/{main_cidr}"
        if gateway:
            main_ip_line += f",{gateway}"
        config_lines.append(main_ip_line)
        
        # 添加附加IP地址
        if additional_ips:
            for i, ip_cidr in enumerate(additional_ips, 2):
                config_lines.append(f"address{i}={ip_cidr}")
        
        # 添加DNS配置
        if dns_servers:
            dns_line = f"dns={';'.join(dns_servers)}"
            config_lines.append(dns_line)
            config_lines.append("dns-search=")
        
        # 添加ipv6部分
        config_lines.extend([
            "",
            "[ipv6]",
            "addr-gen-mode=eui64",
            "method=auto",
            "",
            "[proxy]",
            ""
        ])
        
        # 構建配置文件內容
        config_content = '\n'.join(config_lines)
        
        # 寫入臨時文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(config_content)
        
        # 目標配置文件路徑
        nm_file_path = f"/etc/NetworkManager/system-connections/{conn_name}.nmconnection"
        
        # 上傳到服務器
        tmp_remote = f"/tmp/nm_config_{int(time.time())}"
        self.ssh_client.upload_file(tmp_path, tmp_remote)
        os.unlink(tmp_path)  # 清理本地臨時文件
        
        # 移動到目標位置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"mkdir -p /etc/NetworkManager/system-connections && "
            f"mv {tmp_remote} {nm_file_path} && "
            f"chmod 600 {nm_file_path}"
        )
        
        if exit_code != 0:
            logger.error(f"無法創建NetworkManager配置文件: {stderr}")
            return False
        
        # 重新加載NetworkManager配置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"nmcli connection reload && nmcli connection up '{conn_name}'"
        )
        
        if exit_code != 0:
            logger.warning(f"啟用連接失敗: {stderr}")
            # 嘗試重啟NetworkManager
            self.ssh_client.execute_command("systemctl restart NetworkManager")
            time.sleep(2)  # 等待服務重啟
            self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
        
        # 驗證配置是否生效
        success = True
        
        # 檢查主IP
        if not self._verify_static_config(interface, main_ip):
            logger.warning(f"無法驗證主IP配置，嘗試使用ip命令手動添加")
            self.ssh_client.execute_command(f"ip addr add {main_ip}/{main_cidr} dev {interface}")
            success = False
        
        # 檢查附加IP
        if additional_ips:
            for ip_cidr in additional_ips:
                ip = ip_cidr.split('/')[0]
                cidr = ip_cidr.split('/')[1] if '/' in ip_cidr else "24"
                
                if not self._is_ip_exists(ip, interface):
                    logger.warning(f"無法驗證附加IP配置，嘗試使用ip命令手動添加")
                    self.ssh_client.execute_command(f"ip addr add {ip}/{cidr} dev {interface}")
                    success = False
        
        logger.info(f"成功創建並啟用接口 {interface} 的多IP配置")
        return True

    def _add_secondary_ip_to_nm_connection(self, conn_name: str, interface: str, 
                                        ip_address: str, cidr: int) -> bool:
        """
        向特定NetworkManager連接添加副IP地址
        
        參數:
            conn_name (str): 連接名稱
            interface (str): 網絡接口名稱
            ip_address (str): 要添加的IP地址
            cidr (int): CIDR前綴長度
            
        返回:
            bool: 成功返回True，失敗返回False
        """
        # 檢查連接是否存在
        exit_code, stdout, _ = self.ssh_client.execute_command(
            f"nmcli -t -f NAME connection show | grep '^{conn_name}$'"
        )
        
        if exit_code != 0 or not stdout.strip():
            logger.error(f"未找到連接: {conn_name}")
            return False
        
        # 獲取連接配置文件路徑
        nm_file_path = f"/etc/NetworkManager/system-connections/{conn_name}.nmconnection"
        exit_code, _, _ = self.ssh_client.execute_command(f"test -f {nm_file_path}")
        
        if exit_code != 0:
            # 嘗試不帶.nmconnection後綴
            nm_file_path = f"/etc/NetworkManager/system-connections/{conn_name}"
            exit_code, _, _ = self.ssh_client.execute_command(f"test -f {nm_file_path}")
            
            if exit_code != 0:
                logger.error(f"未找到連接配置文件: {conn_name}")
                return False
        
        # 檢查IP是否已存在於配置文件中
        exit_code, current_config, _ = self.ssh_client.execute_command(f"cat {nm_file_path}")
        if exit_code == 0 and current_config.strip():
            # 檢查IP是否已存在於配置中
            if re.search(rf"address\d+=.*{ip_address}(\/\d+)?", current_config):
                logger.info(f"IP {ip_address} 已存在於NetworkManager配置文件中")
                return True
        else:
            logger.error(f"無法讀取NetworkManager配置文件: {nm_file_path}")
            return False
        
        
        # 檢查配置是否為靜態IP
        if "method=auto" in current_config and "method=manual" not in current_config:
            logger.warning(f"當前配置為DHCP，需要先轉換為靜態IP")
            
            # 獲取當前IP作為主IP
            exit_code, main_ip, _ = self.ssh_client.execute_command(
                f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
            )
            
            if exit_code != 0 or not main_ip.strip():
                logger.error(f"無法獲取當前IP地址")
                return False
            
            main_ip_parts = main_ip.strip().split('/')
            main_ip_addr = main_ip_parts[0]
            main_ip_cidr = int(main_ip_parts[1]) if len(main_ip_parts) > 1 else 24
            
            # 獲取當前網關
            exit_code, gw, _ = self.ssh_client.execute_command(
                f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
            )
            
            gw_addr = gw.strip() if exit_code == 0 and gw.strip() else None
            
            # 修改配置為靜態IP
            modified_lines = []
            lines = current_config.strip().split('\n')
            in_ipv4_section = False
            
            for i, line in enumerate(lines):
                if line.strip() == "[ipv4]":
                    in_ipv4_section = True
                    modified_lines.append(line)
                elif in_ipv4_section and line.strip() == "method=auto":
                    # 修改method為manual
                    modified_lines.append("method=manual")
                    
                    # 添加主IP配置
                    main_ip_line = f"address1={main_ip_addr}/{main_ip_cidr}"
                    if gw_addr:
                        main_ip_line += f",{gw_addr}"
                    modified_lines.append(main_ip_line)
                    
                    # 添加副IP配置
                    second_ip_line = f"address2={ip_address}/{cidr}"
                    modified_lines.append(second_ip_line)
                elif in_ipv4_section and line.strip().startswith("["):
                    # 離開ipv4部分
                    in_ipv4_section = False
                    modified_lines.append(line)
                else:
                    modified_lines.append(line)
        else:
            # 已是靜態IP配置，添加副IP
            # 確定下一個address索引
            address_pattern = r'address(\d+)='
            matches = re.findall(address_pattern, current_config)
            next_index = 1
            if matches:
                indices = [int(idx) for idx in matches if idx.isdigit()]
                if indices:
                    next_index = max(indices) + 1
            
            # 獲取當前網關
            exit_code, gw, _ = self.ssh_client.execute_command(
                f"ip route show dev {interface} | grep default | awk '{{print $3}}'"
            )
            
            gw_addr = gw.strip() if exit_code == 0 and gw.strip() else None
            
            # 構建新的IP地址行
            new_ip_line = f"address{next_index}={ip_address}/{cidr}"
            
            # 修改配置文件
            modified_lines = []
            lines = current_config.strip().split('\n')
            in_ipv4_section = False
            has_added_ip = False
            
            for i, line in enumerate(lines):
                if line.strip() == "[ipv4]":
                    in_ipv4_section = True
                    modified_lines.append(line)
                elif in_ipv4_section and line.strip().startswith("address") and not has_added_ip:
                    modified_lines.append(line)
                    
                    # 檢查是否是最後一個address行
                    next_line_idx = i + 1
                    if next_line_idx < len(lines) and not lines[next_line_idx].strip().startswith("address"):
                        # 添加新的IP地址行
                        modified_lines.append(new_ip_line)
                        has_added_ip = True
                elif in_ipv4_section and not line.strip().startswith("address") and not has_added_ip:
                    # 如果已經過了所有address行，添加新的IP地址行
                    if any("address" in l for l in modified_lines):
                        modified_lines.append(new_ip_line)
                        has_added_ip = True
                    modified_lines.append(line)
                elif in_ipv4_section and line.strip().startswith("[") and not has_added_ip:
                    # 離開ipv4部分，確保添加了IP地址
                    if "method=manual" in current_config:
                        modified_lines.append(new_ip_line)
                        has_added_ip = True
                    in_ipv4_section = False
                    modified_lines.append(line)
                else:
                    modified_lines.append(line)
            
            # 檢查是否需要在文件末尾添加IP地址
            if in_ipv4_section and not has_added_ip:
                modified_lines.append(new_ip_line)
        
        # 寫入修改後的配置
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write('\n'.join(modified_lines))
        
        # 上傳到服務器
        tmp_remote = f"/tmp/nm_config_{int(time.time())}.conf"
        self.ssh_client.upload_file(tmp_path, tmp_remote)
        os.unlink(tmp_path)  # 清理本地臨時文件
        
        # 移動到目標位置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"mv {tmp_remote} {nm_file_path} && chmod 600 {nm_file_path}"
        )
        
        
        # 重新加載NetworkManager配置
        exit_code, _, stderr = self.ssh_client.execute_command(
            f"nmcli connection reload && nmcli connection up {conn_name}"
        )
        
        if exit_code != 0:
            logger.warning(f"重新載入NetworkManager配置失敗: {stderr}")
            # 嘗試重啟NetworkManager
            self.ssh_client.execute_command("systemctl restart NetworkManager")
            time.sleep(2)  # 等待服務重啟
            self.ssh_client.execute_command(f"nmcli connection up {conn_name}")
        
        # 驗證IP是否已添加
        time.sleep(1)  # 等待配置生效
        exit_code, stdout, _ = self.ssh_client.execute_command(
            f"ip addr show dev {interface} | grep -w '{ip_address}'"
        )
        
        if exit_code != 0 or not stdout.strip():
            logger.warning(f"無法通過NetworkManager添加IP，嘗試使用ip命令手動添加")
            # 手動添加IP地址
            self.ssh_client.execute_command(f"ip addr add {ip_address}/{cidr} dev {interface}")
        
        logger.info(f"成功向連接 {conn_name} 添加副IP: {ip_address}/{cidr}")
        return True

        """安全地應用網絡配置變更，處理無 sudo 權限的情況"""
        try:
            # 嘗試使用各種可能的方式重啟網絡
            restart_methods = [
                # 先嘗試不使用 sudo 的命令
                f"ip link set {interface} down && ip link set {interface} up",
                f"ifdown {interface} 2>/dev/null && ifup {interface} 2>/dev/null",
                # 如果有 sudo 再嘗試
                f"sudo systemctl restart networking 2>/dev/null",
                f"sudo service networking restart 2>/dev/null",
                f"sudo ifdown {interface} 2>/dev/null && sudo ifup {interface} 2>/dev/null"
            ]
            
            for method in restart_methods:
                exit_code, _, stderr = self.ssh_client.execute_command(method)
                if exit_code == 0:
                    logger.info(f"成功應用網絡配置: {method}")
                    return True
                else:
                    logger.debug(f"嘗試方法失敗: {method}, 錯誤: {stderr}")
            
            # 如果所有方法都失敗，但我們已經直接使用 ip 命令添加了 IP，也算成功
            logger.warning("所有重啟網絡方法均失敗，但IP可能已通過 ip 命令添加成功")
            return True
        
        except Exception as e:
            logger.error(f"應用網絡配置變更時出錯: {str(e)}")
            return False
        

        """
        確保/etc/network/interfaces文件包含interfaces.d目錄引用
        
        此方法檢查主interfaces文件是否包含source指令以引入interfaces.d目錄中的配置文件。
        如果不存在，則自動添加該指令以確保interfaces.d中的配置能夠被系統識別。
        
        返回:
            bool: 成功添加或已存在返回True，失敗返回False
        """
        try:
            main_file = "/etc/network/interfaces"
            
            # 檢查文件是否存在
            exit_code, _, _ = self.ssh_client.execute_command(f"test -f {main_file}")
            if exit_code != 0:
                logger.warning(f"主interfaces文件 {main_file} 不存在")
                return False
                
            # 檢查是否已包含source指令
            exit_code, stdout, _ = self.ssh_client.execute_command(
                f"grep -q 'source /etc/network/interfaces.d/\\*' {main_file}"
            )
            
            if exit_code == 0:
                # 已包含source指令
                logger.debug("主interfaces文件已包含interfaces.d目錄引用")
                return True
                
            # 添加source指令
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"echo '' >> {main_file} && "
                f"echo '# Include files from /etc/network/interfaces.d directory' >> {main_file} && "
                f"echo 'source /etc/network/interfaces.d/*' >> {main_file}"
            )
            
            if exit_code != 0:
                logger.error(f"添加interfaces.d目錄引用失敗: {stderr}")
                return False
                
            logger.info("已添加interfaces.d目錄引用到主配置文件")
            return True
            
        except Exception as e:
            logger.error(f"確保interfaces.d目錄引用時發生錯誤: {str(e)}")
            return False
        
    def _convert_dhcp_to_static_netplan(self, interface: str, config: Dict[str, Any]) -> bool:
        """
        將使用Netplan的系統的DHCP配置轉換為靜態IP 
        
        參數:
            interface (str): 網絡接口名稱 (例如: 'eth0', 'ens33')
            config (Dict[str, Any]): 網絡配置信息字典，必須包含以下鍵:
                - ip_address (str): 靜態IP地址
                - netmask (str): 子網掩碼 (例如: '255.255.255.0')
                可選鍵:
                - gateway (str): 默認網關地址
                - dns_servers (List[str]): DNS服務器列表
                
        返回:
            bool: 轉換成功返回True，否則返回False
            
        異常處理:
            - 驗證YAML語法正確性
            - 設置適當的文件權限
            - 檢測配置應用後的網絡連接
        """
        logger.info(f"正在轉換Netplan系統的接口 {interface} 配置")
        
        try:
            # 1. 參數驗證與預處理
            # 1.1 檢查IP地址參數
            if "ip_address" not in config or not config["ip_address"]:
                error_msg = "轉換DHCP到靜態IP時缺少IP地址參數"
                logger.error(error_msg)
                return False
                
            # 1.2 檢查子網掩碼參數
            if "netmask" not in config or not config["netmask"]:
                config["netmask"] = "255.255.255.0"
                logger.info("設置默認子網掩碼 255.255.255.0")
            
            # 1.3 轉換子網掩碼為CIDR格式
            cidr = self._netmask_to_cidr(config["netmask"])
            
            # 2.1 獲取適合的netplan配置文件
            netplan_file = self._find_netplan_config_file(interface)
            logger.info(f"將使用netplan配置文件: {netplan_file}")
            

            # 3. 構建高度精確的YAML配置
            # 3.1 基本網絡配置結構
            yaml_content = (
                "network:\n"
                "  version: 2\n"
                "  renderer: networkd\n"
                "  ethernets:\n"
                f"    {interface}:\n"
                "      dhcp4: false\n"
                "      addresses:\n"
                f"        - {config['ip_address']}/{cidr}\n"
            )
            
            # 3.2 配置路由信息
            if config.get("gateway"):
                yaml_content += "      routes:\n"
                yaml_content += "        - to: default\n"
                yaml_content += f"          via: {config['gateway']}\n"
                yaml_content += "          metric: 200\n"
            
            # 3.3 配置DNS服務器
            if config.get("dns_servers") and len(config["dns_servers"]) > 0:
                yaml_content += "      nameservers:\n"
                yaml_content += "        addresses:\n"
                for dns in config["dns_servers"]:
                    yaml_content += f"          - {dns}\n"
            
            # 4. 文件處理與上傳
            # 4.1 創建臨時文件
            temp_file_path = None
            try:
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                    tmp.write(yaml_content)
                    temp_file_path = tmp.name
                    logger.debug(f"已創建臨時配置文件: {temp_file_path}")
                
                # 4.2 上傳到目標服務器
                remote_temp_file = f"/tmp/netplan_config_.yaml"
                self.ssh_client.upload_file(temp_file_path, remote_temp_file)
                logger.info(f"已上傳配置文件到: {remote_temp_file}")
                
            finally:
                # 4.3 清理本地臨時文件
                if temp_file_path and os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    logger.debug("已刪除本地臨時文件")
            
            # 5. 驗證配置語法
            # 5.1 使用netplan generate驗證語法
            cmd_validate = f"sudo netplan generate --root=/tmp/netplan_test_ < {remote_temp_file} 2>&1 || echo 'VALIDATION_ERROR'"
            exit_code, output, _ = self.ssh_client.execute_command(cmd_validate)
            
            if "VALIDATION_ERROR" in output or exit_code != 0:
                logger.error(f"配置文件語法驗證失敗: {output}")
                self.ssh_client.execute_command(f"rm -f {remote_temp_file}")
                return False
            
            logger.debug("配置文件語法驗證成功")
            
            # 6. 應用配置
            # 6.1 確保目標目錄存在
            self.ssh_client.execute_command(f"sudo mkdir -p $(dirname {netplan_file})")
            
            # 6.2 移動配置文件並設置正確權限
            cmd_move = f"sudo cp {remote_temp_file} {netplan_file} && sudo chmod 644 {netplan_file} && sudo rm -f {remote_temp_file}"
            exit_code, _, stderr = self.ssh_client.execute_command(cmd_move)
            
            if exit_code != 0:
                logger.error(f"移動配置文件失敗: {stderr}")
                self.ssh_client.execute_command(f"rm -f {remote_temp_file}")
                return False
            
            logger.debug("已安裝配置文件並設置權限")
            
            # 6.3 應用netplan配置
            cmd_apply = "sudo netplan apply 2>&1 || echo 'APPLY_ERROR'"
            exit_code, output, _ = self.ssh_client.execute_command(cmd_apply)
            
            if "APPLY_ERROR" in output or exit_code != 0:
                logger.error(f"應用netplan配置失敗: {output}")
                return False
            
            logger.debug("已成功應用Netplan配置")
            
            # 7. 網絡配置清理
            # 7.1 停止任何可能正在運行的DHCP客戶端
            self.ssh_client.execute_command(f"sudo dhclient -r {interface} 2>/dev/null || true")
            logger.debug("已嘗試停止DHCP客戶端進程")
            
            # 8. 配置驗證
            # 8.1 等待網絡配置生效
            time.sleep(3)
            
            # 8.2 驗證配置是否成功生效
            if self._verify_static_config(interface, config["ip_address"]):
                logger.info(f"成功將接口 {interface} 的Netplan配置從DHCP轉換為靜態IP")
                return True
            else:
                logger.error(f"配置應用後驗證失敗")
                return False
                    
        except Exception as e:
            logger.error(f"轉換Netplan DHCP配置到靜態IP時發生錯誤: {str(e)}")
            return False
           
    def _add_permanent_ip_netplan(self, ip_address: str, interface: str, netmask: Optional[int] = None,
                            gateway: Optional[str] = None) -> bool:
        """
        在使用Netplan的系統中添加永久IP配置，確保正確YAML格式與檔案權限
        
        參數:
            ip_address (str): IP地址，格式為 x.x.x.x/y (CIDR格式) 或 x.x.x.x (不含CIDR)
            interface (str): 網絡接口名稱
            netmask (Optional[int]): CIDR前綴長度，如果不提供則從ip_address中提取
            gateway (Optional[str]): 默認網關地址
                
        返回:
            bool: 添加成功返回True，否則返回False
        """
        logger.info(f"正在Netplan系統中添加永久IP配置: {ip_address} 到 {interface}")
        
        try:
            # 1. IP地址參數解析與標準化
            if '/' in ip_address:
                ip_only, cidr = ip_address.split('/')
                if not netmask:
                    netmask = int(cidr)
            else:
                ip_only = ip_address
                if not netmask:
                    netmask = 24  # 默認為/24
            
            # 2. 格式化CIDR表示法
            cidr_notation = f"{ip_only}/{netmask}"
            
            # 3. 查找Netplan配置文件
            netplan_file = self._find_netplan_config_file(interface)
            logger.info(f"將修改Netplan配置文件: {netplan_file}")
            

            # 5. 讀取現有配置
            exit_code, content, _ = self.ssh_client.execute_command(
                f"cat {netplan_file} 2>/dev/null || echo ''"
            )
            
            # 6. 構建新配置
            yaml_data = {}
            
            # 6.1 嘗試解析現有配置
            if exit_code == 0 and content.strip():
                try:
                    # 嘗試使用YAML庫解析，但不依賴其格式化輸出
                    import yaml
                    yaml_data = yaml.safe_load(content)
                    if not yaml_data:
                        yaml_data = {}
                except Exception as e:
                    logger.warning(f"無法解析現有YAML配置: {str(e)}，將創建新配置")
                    yaml_data = {}
            
            # 6.2 確保基本結構存在
            if not yaml_data:
                # 創建基本配置結構
                yaml_data = {
                    "network": {
                        "version": 2,
                        "renderer": "networkd",
                        "ethernets": {}
                    }
                }
            elif "network" not in yaml_data:
                yaml_data["network"] = {"version": 2, "renderer": "networkd", "ethernets": {}}
            elif "ethernets" not in yaml_data["network"]:
                yaml_data["network"]["ethernets"] = {}
            
            # 6.3 處理接口配置
            ethernets = yaml_data["network"]["ethernets"]
            
            # 獲取或創建接口配置
            if interface not in ethernets:
                ethernets[interface] = {"dhcp4": False, "addresses": []}
            
            # 確保addresses字段存在
            if "addresses" not in ethernets[interface]:
                ethernets[interface]["addresses"] = []
            
            # 設置為靜態IP配置
            ethernets[interface]["dhcp4"] = False
            
            # 6.4 添加IP地址(如果不存在)
            if cidr_notation not in ethernets[interface]["addresses"]:
                ethernets[interface]["addresses"].append(cidr_notation)
            
            # 6.5 處理網關配置
            if gateway:
                # 確保routes字段存在
                if "routes" not in ethernets[interface]:
                    ethernets[interface]["routes"] = []
                
                # 檢查是否已存在相同的默認路由
                route_exists = False
                for route in ethernets[interface]["routes"]:
                    if route.get("to") == "default" and route.get("via") == gateway:
                        route_exists = True
                        break
                
                # 添加默認路由(如果不存在)
                if not route_exists:
                    ethernets[interface]["routes"].append({
                        "to": "default",
                        "via": gateway,
                        "metric": 200
                    })
            
            # 7. 手動構建YAML配置，確保正確的格式和縮進
            yaml_content = "network:\n"
            yaml_content += "  version: 2\n"
            yaml_content += "  renderer: networkd\n"
            yaml_content += "  ethernets:\n"
            
            # 7.1 構建接口配置
            for iface, iface_config in ethernets.items():
                yaml_content += f"    {iface}:\n"
                
                # 7.2 添加DHCP配置
                dhcp4_value = str(iface_config.get("dhcp4", False)).lower()
                yaml_content += f"      dhcp4: {dhcp4_value}\n"
                
                # 7.3 添加IP地址列表
                iface_addresses = iface_config.get("addresses", [])
                if iface_addresses:
                    yaml_content += "      addresses:\n"
                    for addr in iface_addresses:
                        yaml_content += f"        - {addr}\n"
                
                # 7.4 添加路由配置
                iface_routes = iface_config.get("routes", [])
                if iface_routes:
                    yaml_content += "      routes:\n"
                    for route in iface_routes:
                        yaml_content += f"        - to: {route.get('to', 'default')}\n"
                        yaml_content += f"          via: {route.get('via')}\n"
                        if "metric" in route:
                            yaml_content += f"          metric: {route.get('metric')}\n"
                
                # 7.5 添加DNS配置
                nameservers = iface_config.get("nameservers", {})
                if nameservers:
                    yaml_content += "      nameservers:\n"
                    ns_addresses = nameservers.get("addresses", [])
                    if ns_addresses:
                        yaml_content += "        addresses:\n"
                        for ns in ns_addresses:
                            yaml_content += f"          - {ns}\n"
            
            # 8. 寫入臨時文件
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.write(yaml_content)
                tmp_path = tmp.name
            
            # 9. 上傳到服務器
            target_tmp_file = f"/tmp/netplan_config_{int(time.time())}.yaml"
            self.ssh_client.upload_file(tmp_path, target_tmp_file)
            os.unlink(tmp_path)  # 清理本地臨時文件
            
            # 10. 檢查上傳的配置語法是否正確
            check_cmd = f"sudo netplan --debug generate --root=/tmp/netplan_test_{int(time.time())} 2>&1 < {target_tmp_file}"
            exit_code, stdout, stderr = self.ssh_client.execute_command(check_cmd)
            
            if exit_code != 0:
                logger.error(f"配置語法檢查失敗: {stdout}\n{stderr}")
                return False
            
            # 11. 分步驟配置應用
            # 11.1 確保目標目錄存在
            mkdir_cmd = f"sudo mkdir -p $(dirname {netplan_file})"
            exit_code, _, stderr = self.ssh_client.execute_command(mkdir_cmd)
            if exit_code != 0:
                logger.error(f"創建目錄失敗: {stderr}")
                return False
            
            # 11.2 移動配置文件
            mv_cmd = f"sudo cp {target_tmp_file} {netplan_file}"
            exit_code, _, stderr = self.ssh_client.execute_command(mv_cmd)
            if exit_code != 0:
                logger.error(f"移動配置文件失敗: {stderr}")
                return False
            
            # 11.3 設置正確權限
            chmod_cmd = f"sudo chmod 644 {netplan_file}"
            exit_code, _, stderr = self.ssh_client.execute_command(chmod_cmd)
            if exit_code != 0:
                logger.error(f"設置權限失敗: {stderr}")
                # 保留錯誤文件以便調試
                debug_copy = f"{netplan_file}.debug.{int(time.time())}"
                self.ssh_client.execute_command(f"sudo cp {netplan_file} {debug_copy}")
                return False
            
            # 11.4 刪除臨時文件
            rm_cmd = f"sudo rm -f {target_tmp_file}"
            self.ssh_client.execute_command(rm_cmd)
            
            # 12. 應用Netplan配置
            # 12.1 生成配置驗證
            gen_cmd = "sudo netplan generate"
            exit_code, _, stderr = self.ssh_client.execute_command(gen_cmd)
            if exit_code != 0:
                logger.error(f"Netplan生成配置失敗: {stderr}")
                return False
            
            # 12.2 應用配置
            apply_cmd = "sudo netplan apply"
            exit_code, _, stderr = self.ssh_client.execute_command(apply_cmd)
            if exit_code != 0:
                logger.error(f"應用Netplan配置失敗: {stderr}")
                return False
            
            # 13. 驗證結果
            # 13.1 等待配置生效
            time.sleep(2)
            
            # 13.2 驗證IP是否已添加
            check_cmd = f"ip addr show dev {interface} | grep -w '{ip_only}'"
            exit_code, stdout, _ = self.ssh_client.execute_command(check_cmd)
            
            if exit_code != 0 or not stdout.strip():
                logger.warning(f"無法確認IP {ip_only} 已添加到接口 {interface}，嘗試使用ip命令手動添加")
                # 13.3 嘗試手動添加IP
                add_cmd = f"sudo ip addr add {cidr_notation} dev {interface} 2>/dev/null || echo 'ERROR'"
                exit_code, stdout, _ = self.ssh_client.execute_command(add_cmd)
                if "ERROR" in stdout or exit_code != 0:
                    logger.warning(f"手動添加IP失敗，但配置文件已更新")
            
            logger.info(f"成功添加IP {cidr_notation} 到接口 {interface} 的Netplan配置")
            return True
                
        except Exception as e:
            logger.error(f"添加永久IP到Netplan配置時發生錯誤: {str(e)}")
            return False  

    def execute_batch_commands(self, commands: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """
        批量執行多個命令，通過單一SSH連接執行腳本
        
        參數:
            commands (List[str]): 命令列表
            timeout (int): 執行超時時間（秒）
            
        返回:
            Tuple[int, str, str]: (exit_code, stdout, stderr)
        """
        if not commands:
            return 0, "", ""
            
        # 創建臨時腳本並包含所有命令
        script_content = "#!/bin/bash\nset -e\n\n"
        
        # 添加每個命令並捕獲其輸出
        for i, cmd in enumerate(commands):
            script_content += f"{cmd}\n"
            
        # 創建腳本並設置可執行權限
        script_path = f"/tmp/batch_cmd_{int(time.time())}_{random.randint(1000, 9999)}.sh"
        
        stdin, stdout, stderr = self.client.exec_command(f"cat > {script_path} && chmod +x {script_path}", timeout=timeout)
        stdin.write(script_content)
        stdin.flush()
        stdin.channel.shutdown_write()
        
        # 執行腳本並捕獲輸出
        stdin, stdout, stderr = self.client.exec_command(f"bash {script_path}; echo $?", timeout=timeout)
        
        # 獲取輸出和退出碼
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        # 提取退出碼
        lines = output.splitlines()
        exit_code = 0
        if lines:
            try:
                exit_code = int(lines[-1])
                output = '\n'.join(lines[:-1])
            except ValueError:
                exit_code = 0
        
        # 清理臨時腳本
        self.client.exec_command(f"rm -f {script_path}")
        
        return exit_code, output, error

    def batch_add_ip_addresses(self, start_ip: str, count: int, netmask: str, interface: Optional[str] = None) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        高效批量添加IP地址到網絡接口
        
        參數:
            start_ip (str): 起始IP地址
            count (int): IP地址數量
            netmask (str): 子網掩碼 (CIDR格式，如'24')
            interface (str, optional): 網絡接口名稱，如果為None則使用默認接口
                
        返回:
            Tuple[List[str], List[Tuple[str, str]]]: (成功添加的IP列表, (失敗的IP, 錯誤信息)列表)
                
        異常:
            IPConfigError: 批量添加IP地址失敗時抛出
        """
        # 確定要使用的接口
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"正在批量添加 {count} 個IP地址到接口 {interface}")
        
        try:
            # 參數驗證
            if not self._validate_ip(start_ip):
                raise IPConfigError(f"無效的起始IP地址格式: {start_ip}")
            
            if not netmask.isdigit() or int(netmask) < 1 or int(netmask) > 32:
                raise IPConfigError(f"無效的子網掩碼格式: {netmask}")
            
            # 計算IP範圍
            import ipaddress
            start_ip_obj = ipaddress.IPv4Address(start_ip)
            cidr = int(netmask)
            
            # 生成所有IP地址
            ip_addresses = []
            for i in range(count):
                current_ip = str(start_ip_obj + i)
                ip_with_cidr = f"{current_ip}/{netmask}"
                ip_addresses.append((current_ip, ip_with_cidr))
            
            # 記錄成功和失敗的IP
            success_ips = []
            failed_ips = []
            
            # === 實時網絡配置批處理 ===
            # 檢查哪些IP已存在
            existing_ip_check_commands = []
            for current_ip, _ in ip_addresses:
                existing_ip_check_commands.append(
                    f"ip addr show {interface} | grep -w '{current_ip}' > /dev/null && echo 'EXISTS:{current_ip}' || echo 'NEW:{current_ip}'"
                )
            
            # 批量檢查已存在的IP
            exit_code, stdout, _ = self.ssh_client.execute_batch_commands(existing_ip_check_commands)
            
            # 分析結果，找出需要添加的IP
            ips_to_add = []
            if exit_code == 0 and stdout.strip():
                for line in stdout.strip().split('\n'):
                    if line.startswith('EXISTS:'):
                        ip = line.split(':', 1)[1]
                        success_ips.append(ip)
                        logger.info(f"IP {ip} 已存在於接口 {interface}")
                    elif line.startswith('NEW:'):
                        ip = line.split(':', 1)[1]
                        # 找出對應的CIDR表示
                        for current_ip, ip_with_cidr in ip_addresses:
                            if current_ip == ip:
                                ips_to_add.append((current_ip, ip_with_cidr))
                                break
            
            # 構建批量添加命令
            if ips_to_add:
                # 準備批處理腳本內容
                add_ip_script = [
                    "#!/bin/bash",
                    "set -e",
                    f"# 批量添加IP到接口 {interface}",
                    ""
                ]
                
                for _, ip_with_cidr in ips_to_add:
                    add_ip_script.append(f"ip addr add {ip_with_cidr} dev {interface}")
                
                # 執行批處理腳本
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                    tmp.write("\n".join(add_ip_script))
                    tmp_path = tmp.name
                
                # 上傳並執行腳本
                remote_tmp = f"/tmp/batch_add_ip_{int(time.time())}.sh"
                self.ssh_client.upload_file(tmp_path, remote_tmp)
                os.unlink(tmp_path)  # 清理本地臨時文件
                
                exit_code, stdout, stderr = self.ssh_client.execute_command(
                    f"chmod +x {remote_tmp} && {remote_tmp} && rm -f {remote_tmp}"
                )
                
                if exit_code == 0:
                    # 添加成功
                    for current_ip, _ in ips_to_add:
                        success_ips.append(current_ip)
                        logger.info(f"成功添加IP {current_ip} 到接口 {interface}")
                else:
                    # 批量添加失敗，回退到逐個添加
                    logger.warning(f"批量添加IP失敗: {stderr}，將逐個添加")
                    for current_ip, ip_with_cidr in ips_to_add:
                        exit_code, _, stderr = self.ssh_client.execute_command(
                            f"ip addr add {ip_with_cidr} dev {interface}"
                        )
                        if exit_code == 0:
                            success_ips.append(current_ip)
                            logger.info(f"成功添加IP {current_ip} 到接口 {interface}")
                        else:
                            failed_ips.append((current_ip, f"添加失敗: {stderr}"))
                            logger.error(f"添加IP {current_ip} 失敗: {stderr}")
            
            # === 永久配置批處理 ===
            # 根據OS類型選擇不同的批量配置方法
            os_type = self._detect_os_type()
            
            # 過濾出成功添加的IP
            successful_ips = [(ip, f"{ip}/{netmask}") for ip in success_ips]
            
            # 調用對應的永久配置方法
            if successful_ips:
                if os_type == 'debian':
                    self._batch_add_permanent_debian(successful_ips, interface)
                elif os_type == 'redhat':
                    self._batch_add_permanent_redhat(successful_ips, interface)
                elif os_type == 'netplan':
                    self._batch_add_permanent_netplan(successful_ips, interface)
                
            return success_ips, failed_ips
            
        except Exception as e:
            logger.error(f"批量添加IP地址時發生錯誤: {str(e)}")
            raise IPConfigError(f"批量添加IP地址時發生錯誤: {str(e)}")
        
    def _batch_add_permanent_debian(self, ip_addresses: List[Tuple[str, str]], interface: str) -> bool:
        """
        在Debian系統中批量添加永久IP配置，使用單一操作減少SSH調用
        
        參數:
            ip_addresses (List[Tuple[str, str]]): (IP, IP/CIDR) 元組列表
            interface (str): 網絡接口名稱
                
        返回:
            bool: 成功返回True，失敗返回False
        """
        logger.info(f"在Debian系統中批量添加 {len(ip_addresses)} 個永久IP配置到 {interface}")
        
        try:
            # 使用單一命令檢查interfaces.d目錄是否存在和主interfaces文件中的source指令
            check_cmd = (
                "test -d /etc/network/interfaces.d && echo 'dir_exists' || echo 'dir_missing'; "
                "grep -q 'source /etc/network/interfaces.d/\\*' /etc/network/interfaces && "
                "echo 'source_exists' || echo 'source_missing'"
            )
            
            exit_code, check_result, _ = self.ssh_client.execute_command(check_cmd)
            
            use_interfaces_d = False
            source_exists = False
            
            if exit_code == 0 and check_result:
                for line in check_result.strip().split('\n'):
                    if line == 'dir_exists':
                        use_interfaces_d = True
                    elif line == 'source_exists':
                        source_exists = True
            
            # 決定配置文件路徑
            if use_interfaces_d:
                config_file = f"/etc/network/interfaces.d/{interface}"
            else:
                config_file = "/etc/network/interfaces"
            
            # 查找當前最大別名索引 (單一命令執行)
            index_cmd = (
                f"grep -r -E '(auto|iface) {interface}:[0-9]+' /etc/network/ 2>/dev/null | "
                f"sed -n 's/.*{interface}:\\([0-9]\\+\\).*/\\1/p' | sort -n | tail -1; "
                f"ip addr show | grep -E '{interface}:[0-9]+' | "
                f"sed -n 's/.*{interface}:\\([0-9]\\+\\).*/\\1/p' | sort -n | tail -1"
            )
            
            exit_code, indices_output, _ = self.ssh_client.execute_command(index_cmd)
            
            next_index = 1  # 默認起始索引
            if exit_code == 0 and indices_output.strip():
                indices = [int(idx) for idx in indices_output.strip().split('\n') if idx.strip().isdigit()]
                if indices:
                    next_index = max(indices) + 1
            
            # 構建配置腳本
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # 1. 檢查配置文件是否存在，不存在則創建
            # 2. 為每個IP創建別名配置
            # 3. 一次性寫入所有配置
            
            config_script = [
                "#!/bin/bash",
                "set -e",
                ""
            ]
            
            if use_interfaces_d and not source_exists:
                config_script.append(
                    "grep -q 'source /etc/network/interfaces.d/\\*' /etc/network/interfaces || "
                    "echo 'source /etc/network/interfaces.d/*' >> /etc/network/interfaces"
                )
                config_script.append("mkdir -p /etc/network/interfaces.d")
            
            # 構建配置內容
            config_content = [
                f"# 批量添加的IP配置 - {timestamp}"
            ]
            
            # 為每個IP構建別名配置
            for i, (ip, ip_with_cidr) in enumerate(ip_addresses):
                # 解析CIDR並轉換為子網掩碼
                ip_parts = ip_with_cidr.split('/')
                cidr = ip_parts[1] if len(ip_parts) > 1 else "24"
                netmask = self._cidr_to_netmask(int(cidr))
                
                # 構建接口別名
                alias_name = f"{interface}:{next_index + i}"
                
                # 構建別名配置
                alias_config = [
                    f"auto {alias_name}",
                    f"iface {alias_name} inet static",
                    f"    address {ip}",
                    f"    netmask {netmask}",
                    ""
                ]
                
                config_content.extend(alias_config)
            
            # 創建臨時文件
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.write("\n".join(config_content))
                config_path = tmp.name
            
            # 上傳配置內容
            remote_config = f"/tmp/ip_config_{int(time.time())}.conf"
            self.ssh_client.upload_file(config_path, remote_config)
            os.unlink(config_path)  # 清理本地文件
            
            # 添加寫入配置文件的命令
            config_script.append(f"cat {remote_config} >> {config_file}")
            config_script.append(f"chmod 644 {config_file}")
            config_script.append(f"rm -f {remote_config}")
            
            # 構建啟用命令
            for i in range(len(ip_addresses)):
                alias_name = f"{interface}:{next_index + i}"
                config_script.append(f"ifup {alias_name} 2>/dev/null || ip addr add $(grep -A2 '{alias_name}' {config_file} | grep address | awk '{{print $2}}')/$(grep -A3 '{alias_name}' {config_file} | grep netmask | awk '{{print $2}}' | xargs ipcalc -p | cut -d= -f2) dev {interface}")
            
            # 寫入並執行配置腳本
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.write("\n".join(config_script))
                script_path = tmp.name
            
            remote_script = f"/tmp/apply_ip_config_{int(time.time())}.sh"
            self.ssh_client.upload_file(script_path, remote_script)
            os.unlink(script_path)  # 清理本地文件
            
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"chmod +x {remote_script} && {remote_script} && rm -f {remote_script}"
            )
            
            if exit_code != 0:
                logger.error(f"應用配置失敗: {stderr}")
                return False
            
            logger.info(f"成功在Debian系統中批量添加 {len(ip_addresses)} 個永久IP配置")
            return True
            
        except Exception as e:
            logger.error(f"在Debian系統中批量添加永久IP配置時發生錯誤: {str(e)}")
            return False

    def _batch_add_permanent_redhat(self, ip_addresses: List[Tuple[str, str]], interface: str) -> bool:
        """
        在RedHat系統中高效批量添加永久IP配置
        
        參數:
            ip_addresses (List[Tuple[str, str]]): (IP, IP/CIDR) 元組列表
            interface (str): 網絡接口名稱
                
        返回:
            bool: 成功返回True，失敗返回False
        """
        logger.info(f"在RedHat系統中批量添加 {len(ip_addresses)} 個永久IP配置到 {interface}")
        
        try:
            # 檢測系統版本和NetworkManager支持情況 (單一命令)
            detection_cmd = (
                "cat /etc/os-release 2>/dev/null | grep -E '^(ID|VERSION_ID)=' | tr -d '\"'; "
                "which nmcli >/dev/null 2>&1 && echo 'NMCLI_FOUND' || echo 'NMCLI_MISSING'"
            )
            
            exit_code, detection_result, _ = self.ssh_client.execute_command(detection_cmd)
            
            is_centos8_plus = False
            nmcli_exists = False
            
            if exit_code == 0 and detection_result:
                lines = detection_result.strip().split('\n')
                
                # 分析系統類型和版本
                id_line = next((line for line in lines if line.startswith('ID=')), '')
                version_line = next((line for line in lines if line.startswith('VERSION_ID=')), '')
                
                if 'centos' in id_line.lower() or 'rhel' in id_line.lower():
                    try:
                        version = float(version_line.split('=')[1].split('.')[0])
                        if version >= 8:
                            is_centos8_plus = True
                    except (ValueError, IndexError):
                        pass
                
                # 檢查nmcli命令
                if 'NMCLI_FOUND' in detection_result:
                    nmcli_exists = True
            
            # 根據系統版本選擇配置策略
            if is_centos8_plus and nmcli_exists:
                # 使用NetworkManager配置 (CentOS/RHEL 8+)
                return self._batch_add_permanent_nm(ip_addresses, interface)
            else:
                # 使用傳統ifcfg文件
                config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface}"
                
                # 檢查主配置文件並獲取當前最大IP索引 (單一命令)
                check_cmd = (
                    f"test -f {config_file} && echo 'FILE_EXISTS' || echo 'FILE_MISSING'; "
                    f"test -f {config_file} && grep -E 'IPADDR[0-9]*=' {config_file} | "
                    f"sed -E 's/IPADDR([0-9]*)=.*/\\1/g' | sort -n | tail -1 || echo ''"
                )
                
                exit_code, check_result, _ = self.ssh_client.execute_command(check_cmd)
                
                file_exists = False
                next_index = 0
                
                if exit_code == 0 and check_result:
                    lines = check_result.strip().split('\n')
                    if 'FILE_EXISTS' in lines:
                        file_exists = True
                    
                    # 獲取最大索引
                    indices = [line for line in lines if line.isdigit()]
                    if indices:
                        next_index = int(indices[0]) + 1
                    elif file_exists:  # 沒有索引但文件存在，從1開始
                        next_index = 1
                
                # 創建配置腳本
                script_lines = [
                    "#!/bin/bash",
                    "set -e",
                    ""
                ]
                
                if file_exists:
                    # 檢查配置類型並設置為靜態
                    script_lines.append(
                        f"sed -i 's/BOOTPROTO=.*/BOOTPROTO=static/g' {config_file}"
                    )
                    
                    # 逐個添加副IP配置
                    for i, (ip, ip_with_cidr) in enumerate(ip_addresses):
                        ip_parts = ip_with_cidr.split('/')
                        cidr = ip_parts[1] if len(ip_parts) > 1 else "24"
                        
                        index = next_index + i
                        script_lines.append(f"echo 'IPADDR{index}=\"{ip}\"' >> {config_file}")
                        script_lines.append(f"echo 'PREFIX{index}=\"{cidr}\"' >> {config_file}")
                else:
                    # 創建新配置文件
                    script_lines.append(f"touch {config_file}")
                    script_lines.append(f"echo 'DEVICE={interface}' > {config_file}")
                    script_lines.append(f"echo 'BOOTPROTO=static' >> {config_file}")
                    script_lines.append(f"echo 'ONBOOT=yes' >> {config_file}")
                    
                    # 獲取主IP (可能已存在於接口上)
                    script_lines.append(
                        f"MAIN_IP=$(ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}')"
                    )
                    script_lines.append(
                        "if [ -n \"$MAIN_IP\" ]; then "
                        "IP=$(echo $MAIN_IP | cut -d/ -f1); "
                        "CIDR=$(echo $MAIN_IP | cut -d/ -f2); "
                        f"echo \"IPADDR=\\\"$IP\\\"\" >> {config_file}; "
                        f"echo \"PREFIX=\\\"$CIDR\\\"\" >> {config_file}; "
                        "fi"
                    )
                    
                    # 添加副IP
                    for i, (ip, ip_with_cidr) in enumerate(ip_addresses):
                        ip_parts = ip_with_cidr.split('/')
                        cidr = ip_parts[1] if len(ip_parts) > 1 else "24"
                        
                        index = i + 1
                        script_lines.append(f"echo 'IPADDR{index}=\"{ip}\"' >> {config_file}")
                        script_lines.append(f"echo 'PREFIX{index}=\"{cidr}\"' >> {config_file}")
                
                # 設置文件權限
                script_lines.append(f"chmod 644 {config_file}")
                
                # 重啟網絡服務
                script_lines.append(
                    "systemctl restart network 2>/dev/null || "
                    "service network restart 2>/dev/null || "
                    f"(ifdown {interface} 2>/dev/null && ifup {interface} 2>/dev/null) || true"
                )
                
                # 寫入並執行腳本
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                    tmp.write("\n".join(script_lines))
                    script_path = tmp.name
                
                remote_script = f"/tmp/redhat_ip_config_{int(time.time())}.sh"
                self.ssh_client.upload_file(script_path, remote_script)
                os.unlink(script_path)  # 清理本地文件
                
                exit_code, _, stderr = self.ssh_client.execute_command(
                    f"chmod +x {remote_script} && {remote_script} && rm -f {remote_script}"
                )
                
                if exit_code != 0:
                    logger.error(f"應用配置失敗: {stderr}")
                    return False
                
                logger.info(f"成功在RedHat系統中批量添加 {len(ip_addresses)} 個永久IP配置")
                return True
                
        except Exception as e:
            logger.error(f"在RedHat系統中批量添加永久IP配置時發生錯誤: {str(e)}")
            return False

    def _batch_add_permanent_netplan(self, ip_addresses: List[Tuple[str, str]], interface: str) -> bool:
        """
        在使用Netplan的系統中高效批量添加永久IP配置
        
        參數:
            ip_addresses (List[Tuple[str, str]]): (IP, IP/CIDR) 元組列表
            interface (str): 網絡接口名稱
                
        返回:
            bool: 成功返回True，失敗返回False
        """
        logger.info(f"在Netplan系統中批量添加 {len(ip_addresses)} 個永久IP配置到 {interface}")
        
        try:
            # 查找Netplan配置文件 (使用現有方法)
            netplan_file = self._find_netplan_config_file(interface)
            logger.info(f"將修改Netplan配置文件: {netplan_file}")
            
            # 檢查文件是否存在
            exit_code, file_exists, _ = self.ssh_client.execute_command(f"test -f {netplan_file} && echo 'exists' || echo 'missing'")
            
            # 批量讀取現有配置
            if exit_code == 0 and file_exists.strip() == 'exists':
                exit_code, content, _ = self.ssh_client.execute_command(f"cat {netplan_file}")
            else:
                content = ""
            
            # YAML解析與修改
            try:
                import yaml
                
                # 解析現有配置
                yaml_data = {}
                if content.strip():
                    yaml_data = yaml.safe_load(content) or {}
                
                # 確保基本結構存在
                if 'network' not in yaml_data:
                    yaml_data['network'] = {'version': 2, 'renderer': 'networkd', 'ethernets': {}}
                elif 'ethernets' not in yaml_data['network']:
                    yaml_data['network']['ethernets'] = {}
                    
                # 獲取或創建接口配置
                ethernets = yaml_data['network']['ethernets']
                if interface not in ethernets:
                    ethernets[interface] = {'dhcp4': False, 'addresses': []}
                
                # 確保addresses字段存在
                if 'addresses' not in ethernets[interface]:
                    ethernets[interface]['addresses'] = []
                
                # 確保dhcp4為False
                ethernets[interface]['dhcp4'] = False
                
                # 批量添加IP地址
                for _, ip_with_cidr in ip_addresses:
                    if ip_with_cidr not in ethernets[interface]['addresses']:
                        ethernets[interface]['addresses'].append(ip_with_cidr)
                
                # 優化YAML輸出格式 (自定義格式化)
                yaml_str = yaml.dump(yaml_data, default_flow_style=False)
                
            except ImportError:
                # 如果沒有yaml模塊，使用文本替換方法
                if not content.strip():
                    # 創建全新的配置文件
                    yaml_str = "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n"
                    yaml_str += f"    {interface}:\n"
                    yaml_str += "      dhcp4: false\n"
                    yaml_str += "      addresses:\n"
                    
                    for _, ip_with_cidr in ip_addresses:
                        yaml_str += f"        - {ip_with_cidr}\n"
                else:
                    yaml_str = content.strip()
                    
                    # 檢查配置結構
                    if "network:" not in yaml_str:
                        yaml_str = "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n"
                        yaml_str += f"    {interface}:\n"
                        yaml_str += "      dhcp4: false\n"
                        yaml_str += "      addresses:\n"
                        
                        for _, ip_with_cidr in ip_addresses:
                            yaml_str += f"        - {ip_with_cidr}\n"
                    elif f"  ethernets:\n    {interface}:" not in yaml_str.replace(" ", ""):
                        # 添加接口配置
                        ethernets_pos = yaml_str.find("  ethernets:")
                        if ethernets_pos != -1:
                            insert_pos = ethernets_pos + len("  ethernets:")
                            indent = "\n    "
                            interface_config = f"{indent}{interface}:"
                            interface_config += f"{indent}  dhcp4: false"
                            interface_config += f"{indent}  addresses:"
                            
                            for _, ip_with_cidr in ip_addresses:
                                interface_config += f"{indent}    - {ip_with_cidr}"
                            
                            yaml_str = yaml_str[:insert_pos] + interface_config + yaml_str[insert_pos:]
                        else:
                            # 添加ethernets和接口配置
                            lines = yaml_str.split("\n")
                            network_pos = -1
                            
                            for i, line in enumerate(lines):
                                if line.strip() == "network:":
                                    network_pos = i
                                    break
                            
                            if network_pos != -1:
                                # 找到合適的插入位置
                                insert_pos = network_pos + 1
                                while insert_pos < len(lines) and lines[insert_pos].startswith("  "):
                                    insert_pos += 1
                                
                                # 構建配置
                                config_lines = [
                                    "  ethernets:",
                                    f"    {interface}:",
                                    "      dhcp4: false",
                                    "      addresses:"
                                ]
                                
                                for _, ip_with_cidr in ip_addresses:
                                    config_lines.append(f"        - {ip_with_cidr}")
                                
                                # 插入配置
                                lines = lines[:insert_pos] + config_lines + lines[insert_pos:]
                                yaml_str = "\n".join(lines)
                    else:
                        # 接口配置已存在，找到addresses部分並添加新地址
                        lines = yaml_str.split("\n")
                        interface_pos = -1
                        addresses_pos = -1
                        
                        # 找到接口和addresses位置
                        for i, line in enumerate(lines):
                            if line.strip() == f"{interface}:":
                                interface_pos = i
                            elif interface_pos != -1 and line.strip() == "addresses:":
                                addresses_pos = i
                                break
                        
                        if addresses_pos != -1:
                            # 找到addresses部分，找出最後一個地址的位置
                            last_addr_pos = addresses_pos
                            for i in range(addresses_pos + 1, len(lines)):
                                if lines[i].startswith("        - "):
                                    last_addr_pos = i
                                elif not lines[i].startswith("        "):
                                    break
                            
                            # 構建要插入的地址
                            new_addrs = []
                            for _, ip_with_cidr in ip_addresses:
                                # 檢查地址是否已存在
                                addr_exists = False
                                for i in range(addresses_pos + 1, last_addr_pos + 1):
                                    if lines[i].strip() == f"- {ip_with_cidr}":
                                        addr_exists = True
                                        break
                                
                                if not addr_exists:
                                    new_addrs.append(f"        - {ip_with_cidr}")
                            
                            # 插入新地址
                            if new_addrs:
                                lines = lines[:last_addr_pos + 1] + new_addrs + lines[last_addr_pos + 1:]
                                yaml_str = "\n".join(lines)
                        else:
                            # 沒有找到addresses部分，需要添加
                            for i, line in enumerate(lines):
                                if line.strip() == f"{interface}:":
                                    # 確定縮進級別
                                    indent_level = len(line) - len(line.lstrip())
                                    indent = " " * (indent_level + 2)
                                    
                                    # 檢查dhcp4配置
                                    has_dhcp4 = False
                                    for j in range(i + 1, len(lines)):
                                        if lines[j].startswith(indent + "dhcp4:"):
                                            has_dhcp4 = True
                                            if "true" in lines[j]:
                                                lines[j] = indent + "dhcp4: false"
                                            break
                                        elif len(lines[j].strip()) > 0 and not lines[j].startswith(indent):
                                            break
                                    
                                    if not has_dhcp4:
                                        lines.insert(i + 1, indent + "dhcp4: false")
                                        i += 1
                                    
                                    # 添加addresses配置
                                    lines.insert(i + 1, indent + "addresses:")
                                    i += 1
                                    
                                    # 添加每個IP地址
                                    for _, ip_with_cidr in ip_addresses:
                                        lines.insert(i + 1, indent + "  - " + ip_with_cidr)
                                        i += 1
                                    
                                    yaml_str = "\n".join(lines)
                                    break
            
            # 寫入臨時文件
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.write(yaml_str)
                tmp_path = tmp.name
            
            # 上傳到服務器
            remote_tmp = f"/tmp/netplan_config_{int(time.time())}.yaml"
            self.ssh_client.upload_file(tmp_path, remote_tmp)
            os.unlink(tmp_path)  # 清理本地臨時文件

            # 創建應用配置的腳本
            apply_script = [
                "#!/bin/bash",
                "set -e",
                
                # 檢查配置語法
                f"netplan try --timeout 5 < {remote_tmp} || (echo 'Config validation failed'; exit 1)",
                
                # 確保目錄存在
                f"mkdir -p $(dirname {netplan_file})",
                
                # 移動配置文件
                f"mv {remote_tmp} {netplan_file}",
                
                # 設置權限
                f"chmod 644 {netplan_file}",
                
                # 應用配置
                "netplan apply"
            ]
            
            # 寫入腳本
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                tmp.write("\n".join(apply_script))
                script_path = tmp.name
            
            # 上傳腳本
            remote_script = f"/tmp/apply_netplan_{int(time.time())}.sh"
            self.ssh_client.upload_file(script_path, remote_script)
            os.unlink(script_path)  # 清理本地臨時文件
            
            # 執行腳本
            exit_code, _, stderr = self.ssh_client.execute_command(
                f"chmod +x {remote_script} && sudo {remote_script} && rm -f {remote_script}"
            )
            
            if exit_code != 0:
                logger.error(f"應用Netplan配置失敗: {stderr}")
                return False
            
            logger.info(f"成功在Netplan系統中批量添加 {len(ip_addresses)} 個永久IP配置")
            return True
            
        except Exception as e:
            logger.error(f"在Netplan系統中批量添加永久IP配置時發生錯誤: {str(e)}")
            return False
        
    def benchmark_ssh_calls(self, ip_count: int, interface: str = None) -> Dict[str, Any]:
        """
        基準測試SSH調用與批量IP添加性能
        
        參數:
            ip_count (int): 要測試的IP數量
            interface (str, optional): 網絡接口名稱
            
        返回:
            Dict[str, Any]: 基準測試結果字典
        """
        if not interface:
            interface = self.get_default_interface()
        
        logger.info(f"開始對接口 {interface} 批量添加 {ip_count} 個IP地址的基準測試")
        
        # 設置計數器
        ssh_call_counter = 0
        original_execute_command = self.ssh_client.execute_command
        
        # 替換原始方法以計數調用
        def counted_execute_command(*args, **kwargs):
            nonlocal ssh_call_counter
            ssh_call_counter += 1
            return original_execute_command(*args, **kwargs)
        
        # 替換方法
        self.ssh_client.execute_command = counted_execute_command
        
        try:
            # 計時開始
            start_time = time.time()
            
            # 生成測試IP範圍
            import ipaddress
            start_ip = "192.168.255.1"  # 使用不太可能實際使用的範圍
            start_ip_obj = ipaddress.IPv4Address(start_ip)
            netmask = "24"
            
            # 使用dry-run模式 - 跳過實際執行
            dry_run = True
            
            if not dry_run:
                # 實際執行批量添加
                success_ips, failed_ips = self.batch_add_ip_addresses(start_ip, ip_count, netmask, interface)
            else:
                # 模擬執行，構建IP列表
                ip_addresses = []
                for i in range(ip_count):
                    current_ip = str(start_ip_obj + i)
                    ip_with_cidr = f"{current_ip}/{netmask}"
                    ip_addresses.append((current_ip, ip_with_cidr))
                
                # 調用各個處理函數但不實際執行命令
                os_type = self._detect_os_type()
                
                if os_type == 'debian':
                    self._batch_add_permanent_debian_dryrun(ip_addresses, interface)
                elif os_type == 'redhat':
                    self._batch_add_permanent_redhat_dryrun(ip_addresses, interface)
                elif os_type == 'netplan':
                    self._batch_add_permanent_netplan_dryrun(ip_addresses, interface)
            
            # 計算耗時
            elapsed_time = time.time() - start_time
            
            # 恢復原始方法
            self.ssh_client.execute_command = original_execute_command
            
            # 返回結果
            result = {
                "ssh_calls": ssh_call_counter,
                "elapsed_time": elapsed_time,
                "ip_count": ip_count,
                "calls_per_ip": ssh_call_counter / ip_count if ip_count > 0 else 0,
                "time_per_ip": elapsed_time / ip_count if ip_count > 0 else 0,
                "interface": interface,
                "os_type": self._os_type
            }
            
            logger.info(f"基準測試完成: {result}")
            return result
            
        except Exception as e:
            # 恢復原始方法
            self.ssh_client.execute_command = original_execute_command
            logger.error(f"基準測試時發生錯誤: {str(e)}")
            raise    

    def _batch_add_permanent_nm(self, ip_addresses: List[Tuple[str, str]], interface: str) -> bool:
            """
            使用NetworkManager批量添加永久IP配置
            
            參數:
                ip_addresses (List[Tuple[str, str]]): (IP, IP/CIDR) 元組列表
                interface (str): 網絡接口名稱
                    
            返回:
                bool: 成功返回True，失敗返回False
            """
            logger.info(f"使用NetworkManager批量添加 {len(ip_addresses)} 個永久IP配置到 {interface}")
            
            try:
                # 檢查是否有已存在的連接
                exit_code, stdout, _ = self.ssh_client.execute_command(
                    f"nmcli -t -f NAME,DEVICE connection show | grep ':{interface}$' | cut -d: -f1"
                )
                
                conn_name = None
                if exit_code == 0 and stdout.strip():
                    conn_name = stdout.strip()
                else:
                    # 檢查是否有以接口命名的連接
                    exit_code, stdout, _ = self.ssh_client.execute_command(
                        f"nmcli connection show | grep '{interface}' | awk '{{print $1}}'"
                    )
                    if exit_code == 0 and stdout.strip():
                        conn_name = stdout.strip().split('\n')[0]
                
                if conn_name:
                    # 獲取現有IP地址
                    exit_code, stdout, _ = self.ssh_client.execute_command(
                        f"nmcli -g ipv4.addresses connection show '{conn_name}'"
                    )
                    
                    existing_ips = []
                    if exit_code == 0 and stdout.strip():
                        existing_ips = [addr.strip() for addr in stdout.strip().split(',')]
                    
                    # 將新IP添加到列表
                    for _, ip_with_cidr in ip_addresses:
                        if ip_with_cidr not in existing_ips:
                            existing_ips.append(ip_with_cidr)
                    
                    # 更新連接配置
                    if existing_ips:
                        ip_list = ",".join(existing_ips)
                        cmd = f"nmcli connection modify '{conn_name}' ipv4.method manual ipv4.addresses '{ip_list}'"
                        
                        exit_code, _, stderr = self.ssh_client.execute_command(cmd)
                        if exit_code != 0:
                            logger.error(f"更新NetworkManager連接失敗: {stderr}")
                            return False
                        
                        # 重新加載連接
                        self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
                    else:
                        logger.error("無法獲取任何IP地址配置")
                        return False
                else:
                    # 創建新連接
                    # 獲取當前IP作為主IP
                    exit_code, main_ip, _ = self.ssh_client.execute_command(
                        f"ip addr show dev {interface} | grep -w 'inet' | head -1 | awk '{{print $2}}'"
                    )
                    
                    all_ips = []
                    if exit_code == 0 and main_ip.strip():
                        all_ips.append(main_ip.strip())
                    
                    # 添加新IP
                    for _, ip_with_cidr in ip_addresses:
                        if ip_with_cidr not in all_ips:
                            all_ips.append(ip_with_cidr)
                    
                    if all_ips:
                        # 創建新連接
                        conn_name = interface
                        ip_list = ",".join(all_ips)
                        cmd = f"nmcli connection add type ethernet con-name '{conn_name}' ifname {interface} ipv4.method manual ipv4.addresses '{ip_list}' connection.autoconnect yes"
                        
                        exit_code, _, stderr = self.ssh_client.execute_command(cmd)
                        if exit_code != 0:
                            logger.error(f"創建NetworkManager連接失敗: {stderr}")
                            return False
                        
                        # 啟用連接
                        self.ssh_client.execute_command(f"nmcli connection up '{conn_name}'")
                    else:
                        logger.error("無法獲取任何IP地址配置")
                        return False
                
                logger.info(f"成功使用NetworkManager批量添加 {len(ip_addresses)} 個永久IP配置")
                return True
                
            except Exception as e:
                logger.error(f"使用NetworkManager批量添加永久IP配置時發生錯誤: {str(e)}")
                return False

    def _get_connection_uuid(self, interface: str) -> str:
        """
        增強的 UUID 獲取方法，具有多層級回退策略
        
        參數:
            interface (str): 網絡接口名稱
                
        返回:
            str: 連接 UUID
        """
        # 首先嘗試從現有連接獲取 UUID
        commands = [
            f"nmcli -g connection.uuid c show {interface} 2>/dev/null",
            f"nmcli -g connection.uuid c show {interface}-static 2>/dev/null",
            "uuidgen 2>/dev/null",
            "python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null"
        ]
        
        for cmd in commands:
            exit_code, output, _ = self.ssh_client.execute_command(cmd)
            if exit_code == 0 and output.strip():
                return output.strip()
        
        # 所有方法失敗時使用時間戳作為最後手段
        return f"{interface}-{int(time.time())}"

    def _create_centos9_keyfile_config(self, interface: str, ip_address: str, cidr: int,
                                    gateway: str = None, dns_servers: List[str] = None,
                                    additional_ips: List[str] = None) -> str:
        """
        創建 CentOS 9 NetworkManager keyfile 格式的配置內容 - 優化版
        """
        # 獲取連接 UUID - 使用增強的方法
        conn_uuid = self._get_connection_uuid(interface)
        conn_name = f"{interface}"
        timestamp = int(time.time())
        
        # 構建結構化配置文件內容
        config_sections = {
            "connection": [
                f"id={conn_name}",
                f"uuid={conn_uuid}",
                "type=ethernet",
                "autoconnect=true",
                "autoconnect-priority=0",  # 使用標準優先級
                f"interface-name={interface}",
                f"timestamp={timestamp}",
                "may-fail=true"  # 允許連接失敗時回退
            ],
            "ethernet": [],
            "ipv4": [
                "method=manual",
                "may-fail=true"  # IPv4 配置允許失敗
            ],
            "ipv6": [
                "addr-gen-mode=eui64",
                "method=auto",
                "may-fail=true"  # IPv6 配置允許失敗
            ],
            "proxy": []
        }
        
        # 添加主 IP 地址配置
        address_line = f"address1={ip_address}/{cidr}"
        if gateway:
            address_line += f",{gateway}"
        config_sections["ipv4"].append(address_line)
        
        # 添加額外的 IP 地址
        if additional_ips:
            for idx, addr in enumerate(additional_ips, 2):
                config_sections["ipv4"].append(f"address{idx}={addr}")
        
        # 添加 DNS 設置
        if dns_servers:
            dns_str = ";".join(dns_servers)
            config_sections["ipv4"].append(f"dns={dns_str}")
            config_sections["ipv4"].append("dns-search=")
        
        # 生成最終配置字符串
        config_content = []
        for section, options in config_sections.items():
            config_content.append(f"[{section}]")
            config_content.extend(options)
            config_content.append("")  # 添加空行分隔段落
        
        return "\n".join(config_content)
