#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 對話框組件
實現應用程序中使用的各種對話框

主要對話框:
1. NetworkInterfaceDialog: 網卡詳細信息對話框
2. AboutDialog: 關於對話框
3. SettingsDialog: 設置對話框
"""

import logging
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QGroupBox, QTextEdit, QCheckBox, QTabWidget,
                             QGridLayout, QSpinBox, QDialogButtonBox, QComboBox,
                             QFormLayout, QListWidget, QListWidgetItem, QSizePolicy,
                             QFrame, QWidget)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont, QPixmap

# 使用絕對導入替代相對導入
try:
    # 嘗試直接導入
    from core.config_manager import ConfigManager
except ImportError:
    # 嘗試使用完整包路徑導入
    from ssh_ip_adder.core.config_manager import ConfigManager

# 獲取模塊級別日誌記錄器
logger = logging.getLogger("SSHIPAdder.GUI.Dialogs")

class NetworkInterfaceDialog(QDialog):
    """
    網卡詳細信息對話框
    
    顯示網卡的詳細配置信息，包括:
    - IP地址
    - MAC地址
    - 子網掩碼
    - 網關
    - DNS服務器
    - 配置類型(DHCP/靜態)
    - 狀態
    - 傳輸統計
    """
    
    def __init__(self, parent, interface_name, interface_config):
        """
        初始化網卡詳細信息對話框
        
        參數:
            parent: 父窗口
            interface_name (str): 網卡名稱
            interface_config (dict): 網卡配置信息
        """
        super().__init__(parent)
        
        self.interface_name = interface_name
        self.interface_config = interface_config
        
        self.setWindowTitle(f"網卡詳細信息 - {interface_name}")
        self.resize(600, 400)
        
        self._init_ui()
    
    def _init_ui(self):
        """初始化對話框界面"""
        # 主布局
        layout = QVBoxLayout(self)
        
        # 基本信息組
        basic_group = QGroupBox("基本信息")
        basic_layout = QGridLayout(basic_group)
        
        # 網卡名稱
        basic_layout.addWidget(QLabel("網卡名稱:"), 0, 0)
        basic_layout.addWidget(QLabel(self.interface_name), 0, 1)
        
        # MAC地址
        basic_layout.addWidget(QLabel("MAC地址:"), 1, 0)
        mac_address = self.interface_config.get("mac_address", "未知")
        basic_layout.addWidget(QLabel(mac_address), 1, 1)
        
        # 狀態
        basic_layout.addWidget(QLabel("狀態:"), 2, 0)
        state = "啟用" if self.interface_config.get("is_up", False) else "禁用"
        state_label = QLabel(state)
        state_label.setStyleSheet("color: green" if state == "啟用" else "color: red")
        basic_layout.addWidget(state_label, 2, 1)
        
        # 配置類型
        basic_layout.addWidget(QLabel("配置類型:"), 3, 0)
        config_type = "DHCP" if self.interface_config.get("is_dhcp", False) else "靜態IP"
        basic_layout.addWidget(QLabel(config_type), 3, 1)
        
        layout.addWidget(basic_group)
        
        # IP配置組
        ip_group = QGroupBox("IP配置")
        ip_layout = QGridLayout(ip_group)
        
        # IP地址
        ip_layout.addWidget(QLabel("IP地址:"), 0, 0)
        ip_address = self.interface_config.get("ip_address", "未分配")
        ip_layout.addWidget(QLabel(ip_address), 0, 1)
        
        # 子網掩碼
        ip_layout.addWidget(QLabel("子網掩碼:"), 1, 0)
        netmask = self.interface_config.get("netmask", "未分配")
        ip_layout.addWidget(QLabel(netmask), 1, 1)
        
        # 網關
        ip_layout.addWidget(QLabel("默認網關:"), 2, 0)
        gateway = self.interface_config.get("gateway", "未分配")
        ip_layout.addWidget(QLabel(gateway), 2, 1)
        
        # DNS服務器
        ip_layout.addWidget(QLabel("DNS服務器:"), 3, 0)
        dns_servers = ", ".join(self.interface_config.get("dns_servers", [])) or "未分配"
        ip_layout.addWidget(QLabel(dns_servers), 3, 1)
        
        layout.addWidget(ip_group)
        
        # 統計信息組
        stats_group = QGroupBox("傳輸統計")
        stats_layout = QGridLayout(stats_group)
        
        # 發送字節數
        stats_layout.addWidget(QLabel("發送字節:"), 0, 0)
        tx_bytes = self.interface_config.get("tx_bytes", "未知")
        if isinstance(tx_bytes, int):
            tx_bytes = self._format_bytes(tx_bytes)
        stats_layout.addWidget(QLabel(str(tx_bytes)), 0, 1)
        # 接收字節數
        stats_layout.addWidget(QLabel("接收字節:"), 1, 0)
        rx_bytes = self.interface_config.get("rx_bytes", "未知")
        if isinstance(rx_bytes, int):
            rx_bytes = self._format_bytes(rx_bytes)
        stats_layout.addWidget(QLabel(str(rx_bytes)), 1, 1)
        
        # 發送包數
        stats_layout.addWidget(QLabel("發送包數:"), 2, 0)
        tx_packets = self.interface_config.get("tx_packets", "未知")
        stats_layout.addWidget(QLabel(str(tx_packets)), 2, 1)
        
        # 接收包數
        stats_layout.addWidget(QLabel("接收包數:"), 3, 0)
        rx_packets = self.interface_config.get("rx_packets", "未知")
        stats_layout.addWidget(QLabel(str(rx_packets)), 3, 1)
        
        # 錯誤包數
        stats_layout.addWidget(QLabel("錯誤包數:"), 4, 0)
        errors = self.interface_config.get("errors", "未知")
        stats_layout.addWidget(QLabel(str(errors)), 4, 1)
        
        layout.addWidget(stats_group)
        
        # 提供IP配置文件路徑
        if "config_file" in self.interface_config:
            config_file_group = QGroupBox("配置文件")
            config_file_layout = QVBoxLayout(config_file_group)
            config_file_layout.addWidget(QLabel(self.interface_config["config_file"]))
            layout.addWidget(config_file_group)
        
        # 確定按鈕
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
    
    def _format_bytes(self, bytes_value):
        """
        格式化字節數為可讀形式
        
        參數:
            bytes_value (int): 字節數
            
        返回:
            str: 格式化後的字符串
        """
        # 轉換為合適的單位 (B, KB, MB, GB)
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        value = float(bytes_value)
        
        while value > 1024 and unit_index < len(units) - 1:
            value /= 1024
            unit_index += 1
        
        # 格式化為兩位小數
        return f"{value:.2f} {units[unit_index]}"


class AboutDialog(QDialog):
    """
    關於對話框
    
    顯示應用程序的基本信息:
    - 版本號
    - 作者
    - 許可協議
    - 依賴庫
    - 版權信息
    """
    
    def __init__(self, parent):
        """
        初始化關於對話框
        
        參數:
            parent: 父窗口
        """
        super().__init__(parent)
        
        self.setWindowTitle("關於 SSH IP Adder")
        self.resize(500, 400)
        
        self._init_ui()
    
    def _init_ui(self):
        """初始化對話框界面"""
        # 主布局
        layout = QVBoxLayout(self)
        
        # 標題和版本
        title_label = QLabel("SSH IP Adder")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title_label)
        
        version_label = QLabel("版本 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        # 描述
        description = QLabel("自動添加副IP到遠程Linux雲機的圖形化應用程序")
        description.setAlignment(Qt.AlignCenter)
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # 分隔線
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(line)
        
        # 詳細信息選項卡
        tabs = QTabWidget()
        
        # 關於選項卡
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <p><b>SSH IP Adder</b> 是一款專為系統管理員和雲端環境使用者設計的工具，
        提供圖形化界面，實現通過SSH遠程連接到Linux服務器，自動添加、管理副IP地址的功能。</p>
        
        <p><b>核心功能:</b></p>
        <ul>
            <li>SSH連接管理 (支持密碼和密鑰認證)</li>
            <li>IP地址管理 (添加、檢查IP配置)</li>
            <li>DHCP到靜態IP的轉換</li>
            <li>多種Linux發行版支持</li>
            <li>網絡診斷工具集成</li>
        </ul>
        
        <p><b>特色優勢:</b></p>
        <ul>
            <li>簡化網絡配置流程</li>
            <li>提高工作效率</li>
            <li>降低操作錯誤風險</li>
            <li>適用於各種雲服務環境</li>
        </ul>
        """)
        about_layout.addWidget(about_text)
        
        tabs.addTab(about_tab, "關於")
        
        # 作者選項卡
        authors_tab = QWidget()
        authors_layout = QVBoxLayout(authors_tab)
        
        authors_text = QTextEdit()
        authors_text.setReadOnly(True)
        authors_text.setHtml("""
        <p><b>開發者:</b> Your Name</p>
        <p><b>郵箱:</b> your.email@example.com</p>
        <p><b>網站:</b> https://example.com</p>
        
        <p><b>特別感謝:</b></p>
        <ul>
            <li>Python社區</li>
            <li>PyQt5開發團隊</li>
            <li>Paramiko庫開發者</li>
            <li>所有提供測試和反饋的用戶</li>
        </ul>
        """)
        authors_layout.addWidget(authors_text)
        
        tabs.addTab(authors_tab, "作者")
        
        # 許可協議選項卡
        license_tab = QWidget()
        license_layout = QVBoxLayout(license_tab)
        
        license_text = QTextEdit()
        license_text.setReadOnly(True)
        license_text.setPlainText("""MIT許可協議

版權所有 (c) 2023 Your Name

特此免費授予任何獲得本軟件和相關文檔文件（"軟件"）副本的人不受限制地處理本軟件的權利，
包括但不限於使用、複製、修改、合併、發布、分發、再許可和/或出售本軟件副本的權利，
以及允許獲得本軟件的人這樣做，但須符合以下條件：

上述版權聲明和本許可聲明應包含在本軟件的所有副本或重要部分中。

本軟件按"原樣"提供，不提供任何形式的明示或暗示的保證，包括但不限於適銷性、
特定用途適用性和非侵權性的保證。在任何情況下，作者或版權持有人均不對任何索賠、
損害或其他責任負責，無論是在合同訴訟、侵權行為或其他方面，
由軟件或軟件的使用或其他交易引起的或與之相關的。
        """)
        license_layout.addWidget(license_text)
        
        tabs.addTab(license_tab, "許可協議")
        
        layout.addWidget(tabs)
        
        # 確定按鈕
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class SettingsDialog(QDialog):
    """
    設置對話框
    
    允許用戶配置應用程序的各種設置:
    - 連接設置 (自動連接、保存密碼)
    - 界面設置 (主題、語言)
    - 日誌設置 (日誌級別、保存位置)
    - 網絡超時設置
    """
    
    def __init__(self, parent, config_manager):
        """
        初始化設置對話框
        
        參數:
            parent: 父窗口
            config_manager (ConfigManager): 配置管理器實例
        """
        super().__init__(parent)
        
        self.config_manager = config_manager
        
        self.setWindowTitle("應用程序設置")
        self.resize(500, 400)
        
        self._init_ui()
        self._load_settings()
    
    def _init_ui(self):
        """初始化對話框界面"""
        # 主布局
        layout = QVBoxLayout(self)
        
        # 設置選項卡
        tabs = QTabWidget()
        
        # 連接設置選項卡
        connection_tab = QWidget()
        connection_layout = QVBoxLayout(connection_tab)
        
        # SSH連接設置組
        ssh_group = QGroupBox("SSH連接設置")
        ssh_layout = QFormLayout(ssh_group)
        
        # 自動連接選項
        self.auto_connect_checkbox = QCheckBox("啟動時自動連接到上次的服務器")
        ssh_layout.addRow(self.auto_connect_checkbox)
        
        # 保存密碼選項
        self.save_password_checkbox = QCheckBox("保存SSH密碼")
        ssh_layout.addRow(self.save_password_checkbox)
        
        # 連接超時設置
        timeout_layout = QHBoxLayout()
        self.connection_timeout_spin = QSpinBox()
        self.connection_timeout_spin.setRange(5, 60)
        self.connection_timeout_spin.setValue(10)
        self.connection_timeout_spin.setSuffix(" 秒")
        timeout_layout.addWidget(self.connection_timeout_spin)
        ssh_layout.addRow("連接超時:", timeout_layout)
        
        # 重試設置
        retry_layout = QHBoxLayout()
        self.connection_retry_spin = QSpinBox()
        self.connection_retry_spin.setRange(0, 5)
        self.connection_retry_spin.setValue(1)
        self.connection_retry_spin.setSuffix(" 次")
        retry_layout.addWidget(self.connection_retry_spin)
        ssh_layout.addRow("連接重試次數:", retry_layout)
        
        connection_layout.addWidget(ssh_group)
        
        # IP設置組
        ip_group = QGroupBox("IP地址設置")
        ip_layout = QFormLayout(ip_group)
        
        # 默認子網掩碼
        self.default_netmask_combo = QComboBox()
        self.default_netmask_combo.addItems([
            "255.255.255.0 (/24)", 
            "255.255.255.128 (/25)",
            "255.255.255.192 (/26)",
            "255.255.255.224 (/27)",
            "255.255.255.240 (/28)",
            "255.255.0.0 (/16)",
            "255.0.0.0 (/8)"
        ])
        ip_layout.addRow("默認子網掩碼:", self.default_netmask_combo)
        
        # 默認網卡設置
        self.auto_interface_checkbox = QCheckBox("自動選擇網卡")
        ip_layout.addRow(self.auto_interface_checkbox)
        
        connection_layout.addWidget(ip_group)
        
        # 添加彈性空間
        connection_layout.addStretch()
        
        tabs.addTab(connection_tab, "連接設置")
        
        # 界面設置選項卡
        ui_tab = QWidget()
        ui_layout = QVBoxLayout(ui_tab)
        
        # 外觀設置組
        appearance_group = QGroupBox("外觀設置")
        appearance_layout = QFormLayout(appearance_group)
        
        # 主題選擇
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["系統默認", "亮色主題", "暗色主題"])
        appearance_layout.addRow("主題:", self.theme_combo)
        
        # 字體大小
        font_size_layout = QHBoxLayout()
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 16)
        self.font_size_spin.setValue(9)
        self.font_size_spin.setSuffix(" pt")
        font_size_layout.addWidget(self.font_size_spin)
        appearance_layout.addRow("日誌字體大小:", font_size_layout)
        
        ui_layout.addWidget(appearance_group)
        
        # 日誌設置組
        log_group = QGroupBox("日誌設置")
        log_layout = QFormLayout(log_group)
        
        # 日誌級別
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["調試", "信息", "警告", "錯誤"])
        log_layout.addRow("日誌級別:", self.log_level_combo)
        
        # 日誌保存選項
        self.save_log_checkbox = QCheckBox("保存日誌到文件")
        log_layout.addRow(self.save_log_checkbox)
        
        # 最大日誌文件大小
        log_size_layout = QHBoxLayout()
        self.log_size_spin = QSpinBox()
        self.log_size_spin.setRange(1, 10)
        self.log_size_spin.setValue(1)
        self.log_size_spin.setSuffix(" MB")
        log_size_layout.addWidget(self.log_size_spin)
        log_layout.addRow("最大日誌文件大小:", log_size_layout)
        
        ui_layout.addWidget(log_group)
        
        # 添加彈性空間
        ui_layout.addStretch()
        
        tabs.addTab(ui_tab, "界面設置")
        
        # 高級設置選項卡
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        # 網絡設置組
        network_group = QGroupBox("網絡設置")
        network_layout = QFormLayout(network_group)
        
        # 命令超時設置
        cmd_timeout_layout = QHBoxLayout()
        self.cmd_timeout_spin = QSpinBox()
        self.cmd_timeout_spin.setRange(10, 120)
        self.cmd_timeout_spin.setValue(30)
        self.cmd_timeout_spin.setSuffix(" 秒")
        cmd_timeout_layout.addWidget(self.cmd_timeout_spin)
        network_layout.addRow("命令執行超時:", cmd_timeout_layout)
        
        # 設置確認選項
        self.confirm_settings_checkbox = QCheckBox("修改系統網絡配置前確認")
        network_layout.addRow(self.confirm_settings_checkbox)
        
        # 自動備份網絡配置
        self.backup_config_checkbox = QCheckBox("修改前自動備份網絡配置")
        network_layout.addRow(self.backup_config_checkbox)
        
        advanced_layout.addWidget(network_group)
        
        # 添加彈性空間
        advanced_layout.addStretch()
        
        tabs.addTab(advanced_tab, "高級設置")
        
        layout.addWidget(tabs)
        
        # 按鈕區域
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def _load_settings(self):
        """從配置管理器加載設置"""
        # 連接設置
        self.auto_connect_checkbox.setChecked(
            self.config_manager.get_value("auto_connect", False)
        )
        self.save_password_checkbox.setChecked(
            self.config_manager.get_value("save_password", False)
        )
        self.connection_timeout_spin.setValue(
            self.config_manager.get_value("connection_timeout", 10)
        )
        self.connection_retry_spin.setValue(
            self.config_manager.get_value("connection_retry", 1)
        )
        
        # IP設置
        default_netmask = self.config_manager.get_value("default_netmask", "255.255.255.0 (/24)")
        index = self.default_netmask_combo.findText(default_netmask)
        if index >= 0:
            self.default_netmask_combo.setCurrentIndex(index)
        
        self.auto_interface_checkbox.setChecked(
            self.config_manager.get_value("auto_interface", True)
        )
        
        # 界面設置
        theme = self.config_manager.get_value("theme", "系統默認")
        index = self.theme_combo.findText(theme)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
        
        self.font_size_spin.setValue(
            self.config_manager.get_value("font_size", 9)
        )
        
        # 日誌設置
        log_level = self.config_manager.get_value("log_level", "信息")
        index = self.log_level_combo.findText(log_level)
        if index >= 0:
            self.log_level_combo.setCurrentIndex(index)
        
        self.save_log_checkbox.setChecked(
            self.config_manager.get_value("save_log", True)
        )
        
        self.log_size_spin.setValue(
            self.config_manager.get_value("log_size", 1)
        )
        
        # 高級設置
        self.cmd_timeout_spin.setValue(
            self.config_manager.get_value("cmd_timeout", 30)
        )
        
        self.confirm_settings_checkbox.setChecked(
            self.config_manager.get_value("confirm_settings", True)
        )
        
        self.backup_config_checkbox.setChecked(
            self.config_manager.get_value("backup_config", True)
        )
    
    def accept(self):
        """保存設置並接受對話框"""
        # 收集設置
        settings = {
            # 連接設置
            "auto_connect": self.auto_connect_checkbox.isChecked(),
            "save_password": self.save_password_checkbox.isChecked(),
            "connection_timeout": self.connection_timeout_spin.value(),
            "connection_retry": self.connection_retry_spin.value(),
            
            # IP設置
            "default_netmask": self.default_netmask_combo.currentText(),
            "auto_interface": self.auto_interface_checkbox.isChecked(),
            
            # 界面設置
            "theme": self.theme_combo.currentText(),
            "font_size": self.font_size_spin.value(),
            
            # 日誌設置
            "log_level": self.log_level_combo.currentText(),
            "save_log": self.save_log_checkbox.isChecked(),
            "log_size": self.log_size_spin.value(),
            
            # 高級設置
            "cmd_timeout": self.cmd_timeout_spin.value(),
            "confirm_settings": self.confirm_settings_checkbox.isChecked(),
            "backup_config": self.backup_config_checkbox.isChecked()
        }
        
        # 保存設置
        self.config_manager.save_config(settings)
        
        # 調用父類的accept方法關閉對話框
        super().accept()