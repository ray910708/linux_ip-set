#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: SSH客戶端模塊
負責管理與遠程服務器的SSH連接、認證和命令執行

主要功能:
1. 建立SSH連接（支持密碼和密鑰認證）
2. 執行遠程命令
3. 管理連接狀態和超時
4. 處理錯誤和異常
"""

import os
import logging
import socket
import time
from typing import Optional, Tuple, List, Dict, Any, Union
import paramiko
from paramiko.ssh_exception import (
    AuthenticationException, 
    SSHException, 
    NoValidConnectionsError
)

from .exceptions import SSHConnectionError

# 獲取模塊級別日誌記錄器
logger = logging.getLogger("SSHIPAdder.Core.SSHClient")

class SSHClient:
    """
    SSH客戶端類，負責與遠程服務器的SSH連接管理
    
    主要職責:
    1. 建立和管理SSH連接
    2. 提供命令執行介面
    3. 處理連接錯誤和超時
    4. 維護連接狀態
    """
    
    def __init__(self, timeout: int = 10, retry_count: int = 1, retry_delay: int = 2):
        """
        初始化SSH客戶端
        
        參數:
            timeout (int): 連接超時時間(秒)，默認10秒
            retry_count (int): 連接失敗時的重試次數，默認1次
            retry_delay (int): 重試間隔時間(秒)，默認2秒
        """
        # 初始化Paramiko SSH客戶端
        self.client = paramiko.SSHClient()
        
        # 自動添加未知主機密鑰
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 設置連接參數
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        
        # 連接狀態
        self.connected = False
        
        # 服務器信息
        self.server_info = {}
        
        logger.debug("SSH客戶端初始化完成")
    
    def connect_with_password(self, hostname: str, port: int, username: str, password: str) -> bool:
        """
        使用密碼認證方式連接到SSH服務器
        
        參數:
            hostname (str): 服務器地址
            port (int): SSH端口
            username (str): 用戶名
            password (str): 密碼
            
        返回:
            bool: 連接成功返回True，失敗抛出異常
            
        異常:
            SSHConnectionError: 連接失敗時抛出
        """
        logger.info(f"正在使用密碼認證連接到 {hostname}:{port}")
        
        for attempt in range(self.retry_count + 1):
            try:
                # 如果已連接，先斷開
                if self.connected:
                    self.disconnect()
                
                # 建立SSH連接
                self.client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # 更新連接狀態
                self._update_connection_status(True, hostname, port, username)
                logger.info(f"成功連接到 {hostname}:{port}")
                
                return True
                
            except AuthenticationException:
                logger.error(f"認證失敗: {hostname}:{port}")
                raise SSHConnectionError("認證失敗，請檢查用戶名和密碼")
                
            except (SSHException, NoValidConnectionsError) as e:
                logger.error(f"SSH協議錯誤 ({attempt+1}/{self.retry_count+1}): {str(e)}")
                if attempt < self.retry_count:
                    logger.info(f"將在 {self.retry_delay} 秒後重試")
                    time.sleep(self.retry_delay)
                else:
                    raise SSHConnectionError(f"SSH連接錯誤: {str(e)}")
                
            except socket.timeout:
                logger.error(f"連接超時 ({attempt+1}/{self.retry_count+1}): {hostname}:{port}")
                if attempt < self.retry_count:
                    logger.info(f"將在 {self.retry_delay} 秒後重試")
                    time.sleep(self.retry_delay)
                else:
                    raise SSHConnectionError("連接超時，請檢查網絡或服務器地址")
                
            except socket.error as e:
                logger.error(f"網絡錯誤 ({attempt+1}/{self.retry_count+1}): {str(e)}")
                if attempt < self.retry_count:
                    logger.info(f"將在 {self.retry_delay} 秒後重試")
                    time.sleep(self.retry_delay)
                else:
                    raise SSHConnectionError(f"網絡錯誤: {str(e)}")
                
            except Exception as e:
                logger.error(f"連接失敗: {str(e)}")
                raise SSHConnectionError(f"連接失敗: {str(e)}")
    
    def connect_with_key(self, hostname: str, port: int, username: str, key_path: str, passphrase: str = "") -> bool:
        """
        使用密鑰認證方式連接到SSH服務器
        
        參數:
            hostname (str): 服務器地址
            port (int): SSH端口
            username (str): 用戶名
            key_path (str): 私鑰文件路徑
            passphrase (str, optional): 私鑰密碼，默認為空
            
        返回:
            bool: 連接成功返回True，失敗抛出異常
            
        異常:
            SSHConnectionError: 連接失敗時抛出
        """
        logger.info(f"正在使用密鑰認證連接到 {hostname}:{port}")
        
        # 驗證密鑰文件存在
        if not os.path.isfile(key_path):
            logger.error(f"密鑰文件不存在: {key_path}")
            raise SSHConnectionError(f"密鑰文件不存在: {key_path}")
        
        for attempt in range(self.retry_count + 1):
            try:
                # 如果已連接，先斷開
                if self.connected:
                    self.disconnect()
                
                # 加載私鑰
                try:
                    if passphrase:
                        key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
                    else:
                        key = paramiko.RSAKey.from_private_key_file(key_path)
                except paramiko.ssh_exception.PasswordRequiredException:
                    logger.error("私鑰需要密碼")
                    raise SSHConnectionError("私鑰需要密碼，請提供私鑰密碼")
                except Exception as e:
                    logger.error(f"無法加載私鑰: {str(e)}")
                    raise SSHConnectionError(f"無法加載私鑰: {str(e)}")
                
                # 建立SSH連接
                self.client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    pkey=key,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # 更新連接狀態
                self._update_connection_status(True, hostname, port, username)
                logger.info(f"成功連接到 {hostname}:{port}")
                
                return True
                
            except AuthenticationException:
                logger.error(f"密鑰認證失敗: {hostname}:{port}")
                logger.error(f"密鑰認證失敗: {hostname}:{port}")
                raise SSHConnectionError("密鑰認證失敗，請檢查密鑰文件或密碼")
                
            except (SSHException, NoValidConnectionsError) as e:
                logger.error(f"SSH協議錯誤 ({attempt+1}/{self.retry_count+1}): {str(e)}")
                if attempt < self.retry_count:
                    logger.info(f"將在 {self.retry_delay} 秒後重試")
                    time.sleep(self.retry_delay)
                else:
                    raise SSHConnectionError(f"SSH連接錯誤: {str(e)}")
                
            except socket.timeout:
                logger.error(f"連接超時 ({attempt+1}/{self.retry_count+1}): {hostname}:{port}")
                if attempt < self.retry_count:
                    logger.info(f"將在 {self.retry_delay} 秒後重試")
                    time.sleep(self.retry_delay)
                else:
                    raise SSHConnectionError("連接超時，請檢查網絡或服務器地址")
                
            except socket.error as e:
                logger.error(f"網絡錯誤 ({attempt+1}/{self.retry_count+1}): {str(e)}")
                if attempt < self.retry_count:
                    logger.info(f"將在 {self.retry_delay} 秒後重試")
                    time.sleep(self.retry_delay)
                else:
                    raise SSHConnectionError(f"網絡錯誤: {str(e)}")
                
            except Exception as e:
                logger.error(f"連接失敗: {str(e)}")
                raise SSHConnectionError(f"連接失敗: {str(e)}")
    
    def disconnect(self) -> None:
        """
        斷開SSH連接
        """
        if self.connected:
            try:
                self.client.close()
                logger.info("已斷開SSH連接")
            except Exception as e:
                logger.error(f"斷開連接時發生錯誤: {str(e)}")
            finally:
                self._update_connection_status(False)
    
    def execute_command(self, command: str, timeout: int = 30, get_pty: bool = False) -> Tuple[int, str, str]:
        """
        執行SSH命令並返回結果
        
        參數:
            command (str): 要執行的命令
            timeout (int, optional): 命令執行超時時間(秒)，默認30秒
            get_pty (bool, optional): 是否分配偽終端，默認False
            
        返回:
            Tuple[int, str, str]: (返回碼, 標準輸出, 錯誤輸出)
            
        異常:
            SSHConnectionError: 執行命令失敗時抛出
        """
        if not self.connected or not self.is_connected():
            logger.error("未連接到SSH服務器")
            raise SSHConnectionError("未連接到SSH服務器")
        
        logger.debug(f"執行命令: {command}")
        
        try:
            # 創建新的通道
            transport = self.client.get_transport()
            channel = transport.open_session()
            
            # 設置超時
            channel.settimeout(timeout)
            
            # 分配偽終端（如果需要）
            if get_pty:
                channel.get_pty()
            
            # 執行命令
            channel.exec_command(command)
            
            # 獲取輸出
            stdout = channel.makefile('r', -1)
            stderr = channel.makefile_stderr('r', -1)
            
            # 等待命令完成
            exit_code = channel.recv_exit_status()
            
            # 讀取輸出（將bytes轉換為str）
            stdout_str = stdout.read()
            if isinstance(stdout_str, bytes):
                stdout_str = stdout_str.decode('utf-8', errors='replace')
                
            stderr_str = stderr.read()
            if isinstance(stderr_str, bytes):
                stderr_str = stderr_str.decode('utf-8', errors='replace')
            
            logger.debug(f"命令返回碼: {exit_code}")
            
            if exit_code != 0:
                logger.warning(f"命令執行返回非零狀態: {exit_code}, 錯誤: {stderr_str}")
            
            return exit_code, stdout_str, stderr_str
            
        except socket.timeout:
            logger.error("命令執行超時")
            raise SSHConnectionError("命令執行超時")
            
        except (SSHException, IOError) as e:
            logger.error(f"SSH命令執行錯誤: {str(e)}")
            
            # 檢查是否是由於連接關閉引起的錯誤
            if "Socket is closed" in str(e) or "Channel closed" in str(e):
                self._update_connection_status(False)
                raise SSHConnectionError("SSH連接已關閉，請重新連接")
            
            raise SSHConnectionError(f"SSH命令執行錯誤: {str(e)}")
            
        except Exception as e:
            logger.error(f"執行命令時發生錯誤: {str(e)}")
            raise SSHConnectionError(f"執行命令時發生錯誤: {str(e)}")
    
    def execute_sudo_command(self, command: str, password: str, timeout: int = 30) -> Tuple[int, str, str]:
        """
        使用sudo執行需要提升權限的命令
        
        參數:
            command (str): 要執行的命令（不需要包含sudo前綴）
            password (str): sudo密碼
            timeout (int, optional): 命令執行超時時間(秒)，默認30秒
            
        返回:
            Tuple[int, str, str]: (返回碼, 標準輸出, 錯誤輸出)
            
        異常:
            SSHConnectionError: 執行命令失敗時抛出
        """
        if not self.connected or not self.is_connected():
            logger.error("未連接到SSH服務器")
            raise SSHConnectionError("未連接到SSH服務器")
        
        # 構建sudo命令
        sudo_command = f'echo "{password}" | sudo -S {command}'
        logger.debug(f"執行sudo命令: sudo {command}")
        
        try:
            # 使用get_pty=True來支持sudo命令
            return self.execute_command(sudo_command, timeout, get_pty=True)
            
        except Exception as e:
            logger.error(f"執行sudo命令時發生錯誤: {str(e)}")
            raise SSHConnectionError(f"執行sudo命令時發生錯誤: {str(e)}")
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        將本地文件上傳到遠程服務器
        
        參數:
            local_path (str): 本地文件路徑
            remote_path (str): 遠程文件路徑
            
        返回:
            bool: 上傳成功返回True，失敗抛出異常
            
        異常:
            SSHConnectionError: 上傳失敗時抛出
        """
        if not self.connected or not self.is_connected():
            logger.error("未連接到SSH服務器")
            raise SSHConnectionError("未連接到SSH服務器")
        
        logger.info(f"正在上傳文件: {local_path} -> {remote_path}")
        
        try:
            # 創建SFTP客戶端
            sftp = self.client.open_sftp()
            
            # 上傳文件
            sftp.put(local_path, remote_path)
            
            # 關閉SFTP連接
            sftp.close()
            
            logger.info(f"文件上傳成功: {remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"文件上傳失敗: {str(e)}")
            raise SSHConnectionError(f"文件上傳失敗: {str(e)}")
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        從遠程服務器下載文件到本地
        
        參數:
            remote_path (str): 遠程文件路徑
            local_path (str): 本地文件路徑
            
        返回:
            bool: 下載成功返回True，失敗抛出異常
            
        異常:
            SSHConnectionError: 下載失敗時抛出
        """
        if not self.connected or not self.is_connected():
            logger.error("未連接到SSH服務器")
            raise SSHConnectionError("未連接到SSH服務器")
        
        logger.info(f"正在下載文件: {remote_path} -> {local_path}")
        
        try:
            # 創建SFTP客戶端
            sftp = self.client.open_sftp()
            
            # 下載文件
            sftp.get(remote_path, local_path)
            
            # 關閉SFTP連接
            sftp.close()
            
            logger.info(f"文件下載成功: {local_path}")
            return True
            
        except Exception as e:
            logger.error(f"文件下載失敗: {str(e)}")
            raise SSHConnectionError(f"文件下載失敗: {str(e)}")
    
    def is_connected(self) -> bool:
        """
        檢查SSH連接是否仍然活躍
        
        返回:
            bool: 如果連接活躍返回True，否則返回False
        """
        if not self.connected:
            return False
        
        try:
            transport = self.client.get_transport()
            if transport is None:
                return False
            
            # 檢查transport是否活躍
            is_active = transport.is_active()
            
            # 如果狀態不一致，更新連接狀態
            if self.connected != is_active:
                self._update_connection_status(is_active)
            
            return is_active
            
        except Exception as e:
            logger.error(f"檢查連接狀態時發生錯誤: {str(e)}")
            self._update_connection_status(False)
            return False
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        獲取已連接服務器的信息
        
        返回:
            Dict[str, Any]: 服務器信息字典
        """
        return self.server_info.copy()
    
    def get_connection_time(self) -> Optional[float]:
        """
        獲取連接建立時間
        
        返回:
            Optional[float]: 連接建立時間戳，未連接時返回None
        """
        if not self.connected:
            return None
        
        return self.server_info.get("connected_time")
    
    def get_connection_duration(self) -> Optional[float]:
        """
        獲取連接持續時間
        
        返回:
            Optional[float]: 連接持續時間(秒)，未連接時返回None
        """
        if not self.connected:
            return None
        
        connected_time = self.server_info.get("connected_time")
        if connected_time is None:
            return None
        
        return time.time() - connected_time
    
    def _update_connection_status(self, connected: bool, hostname: str = "", port: int = 0, username: str = "") -> None:
        """
        更新連接狀態信息
        
        參數:
            connected (bool): 連接狀態
            hostname (str, optional): 服務器地址
            port (int, optional): 端口
            username (str, optional): 用戶名
        """
        self.connected = connected
        
        if connected:
            self.server_info = {
                "hostname": hostname,
                "port": port,
                "username": username,
                "connected_time": time.time()
            }
        else:
            # 保留部分信息用於重連
            hostname = self.server_info.get("hostname", "")
            port = self.server_info.get("port", 0)
            username = self.server_info.get("username", "")
            
            self.server_info = {
                "hostname": hostname,
                "port": port,
                "username": username,
                "disconnected_time": time.time()
            }
            