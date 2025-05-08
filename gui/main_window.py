#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH-IP-Adder: 主窗口
實現主窗口界面和所有操作邏輯
"""

import os
import sys
import time
import json
import threading
import logging
import re
from typing import Dict, List, Any, Tuple, Optional, Union

import ipaddress
from PyQt5.QtCore import (
    Qt, QSize, QTimer, pyqtSignal, pyqtSlot, QEvent, QObject, QMetaObject, Q_ARG
)
from PyQt5.QtGui import (
    QIcon, QCloseEvent, QKeySequence, QBrush, QColor, QFont, QTextCursor
)
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QGroupBox, QGridLayout,
    QLineEdit, QComboBox, QCheckBox, QSpinBox, QTextEdit,
    QProgressBar, QStatusBar, QMenu, QAction, QFileDialog,
    QMessageBox, QDialogButtonBox, QFrame, QSplitter, QScrollArea,
    QToolBar
)

# 使用絕對導入替代相對導入
try:
    # 嘗試直接導入
    from core.ssh_client import SSHClient
    from core.ip_manager import IPManager
    from core.config_manager import ConfigManager
    from core.exceptions import SSHConnectionError, IPConfigError, ValidationError
    from gui.dialogs import NetworkInterfaceDialog, AboutDialog, SettingsDialog
    from utils.validators import is_valid_ip, is_valid_hostname, is_valid_port
except ImportError:
    # 嘗試使用完整包路徑導入
    from ssh_ip_adder.core.ssh_client import SSHClient
    from ssh_ip_adder.core.ip_manager import IPManager
    from ssh_ip_adder.core.config_manager import ConfigManager
    from ssh_ip_adder.core.exceptions import SSHConnectionError, IPConfigError, ValidationError
    from ssh_ip_adder.gui.dialogs import NetworkInterfaceDialog, AboutDialog, SettingsDialog
    from ssh_ip_adder.utils.validators import is_valid_ip, is_valid_hostname, is_valid_port

# 獲取模塊級別日誌記錄器
logger = logging.getLogger("SSHIPAdder.GUI.MainWindow")

class MainWindow(QMainWindow):
    """
    應用程序主窗口類
    
    負責:
    1. 創建和管理GUI組件
    2. 處理用戶輸入和事件
    3. 協調SSH連接和IP管理操作
    4. 顯示操作結果和狀態
    """
    
    # 自定義信號 - 用於跨線程UI更新
    update_log_signal = pyqtSignal(str)
    update_status_signal = pyqtSignal(str)
    update_progress_signal = pyqtSignal(int)
    ssh_connected_signal = pyqtSignal(bool)
    ip_added_signal = pyqtSignal(bool, str)
    refresh_interfaces_signal = pyqtSignal(list)
    dhcp_status_signal = pyqtSignal(bool, dict)
    
    def __init__(self, config_manager: ConfigManager):
        """
        初始化主窗口
        
        參數:
            config_manager (ConfigManager): 配置管理器實例
        """
        super().__init__()
        
        # 初始化成員變量
        self.config_manager = config_manager
        self.ssh_client = None
        self.ip_manager = None
        self.is_connected = False
        self.current_server_info = {}
        self.interfaces_list = []
        self.interface_details = {}
        self.dhcp_interfaces = set()
        
        # 設置窗口屬性
        self.setWindowTitle("SSH IP Adder")
        self.resize(900, 700)
        self.setMinimumSize(800, 600)
        
        # 初始化界面
        self._init_ui()
        
        # 連接信號槽
        self._connect_signals()
        
        # 加載保存的配置
        self._load_saved_config()
        
        # 初始化狀態
        self.update_status_signal.emit("就緒")
        self.update_progress_signal.emit(0)
        
        logger.info("主窗口初始化完成")
    
    def _init_ui(self):
        """初始化用戶界面"""
        # 創建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # 創建菜單欄
        self._create_menu_bar()
        
        # 創建工具欄
        self._create_tool_bar()
        
        # 創建分割器
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        
        # 上半部分：配置選項卡
        self.tabs = QTabWidget()
        splitter.addWidget(self.tabs)
        
        # 創建SSH配置選項卡
        ssh_tab = QWidget()
        self.tabs.addTab(ssh_tab, "SSH連接")
        
        # 創建IP配置選項卡
        ip_tab = QWidget()
        self.tabs.addTab(ip_tab, "IP配置")
        
        # 創建網絡工具選項卡
        tools_tab = QWidget()
        self.tabs.addTab(tools_tab, "網絡工具")
        
        # 設置SSH配置選項卡
        self._setup_ssh_tab(ssh_tab)
        
        # 設置IP配置選項卡
        self._setup_ip_tab(ip_tab)
        
        # 設置網絡工具選項卡
        self._setup_tools_tab(tools_tab)
        
        # 下半部分：日誌和狀態
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(log_widget)
        
        # 日誌顯示區
        log_group = QGroupBox("操作日誌")
        log_group_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Monospace", 9))
        log_group_layout.addWidget(self.log_text)
        
        log_layout.addWidget(log_group)
        
        # 底部按鈕區域
        bottom_layout = QHBoxLayout()
        
        # 清除日誌按鈕
        self.clear_log_button = QPushButton("清除日誌")
        self.clear_log_button.clicked.connect(self.clear_log)
        bottom_layout.addWidget(self.clear_log_button)
        
        # 彈性空間
        bottom_layout.addStretch()
        
        # 連接狀態標籤
        self.connection_status_label = QLabel("未連接")
        bottom_layout.addWidget(self.connection_status_label)
        
        # 關於按鈕
        self.about_button = QPushButton("關於")
        self.about_button.clicked.connect(self.show_about_dialog)
        bottom_layout.addWidget(self.about_button)
        
        log_layout.addLayout(bottom_layout)
        
        # 狀態欄
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # 進度條
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMaximumWidth(200)
        self.statusBar.addPermanentWidget(self.progress_bar)
        
        # 設置分割器初始大小
        splitter.setSizes([500, 200])
        
        logger.debug("UI組件初始化完成")
    
    def _create_menu_bar(self):
        """創建菜單欄"""
        # 文件菜單
        file_menu = self.menuBar().addMenu("文件")
        
        # 連接動作
        connect_action = QAction("連接到服務器", self)
        connect_action.setShortcut(QKeySequence("Ctrl+N"))
        connect_action.triggered.connect(self.connect_to_ssh)
        file_menu.addAction(connect_action)
        
        # 斷開連接動作
        disconnect_action = QAction("斷開連接", self)
        disconnect_action.setShortcut(QKeySequence("Ctrl+D"))
        disconnect_action.triggered.connect(self.disconnect_ssh)
        disconnect_action.setEnabled(False)
        self.disconnect_action = disconnect_action
        file_menu.addAction(disconnect_action)
        
        file_menu.addSeparator()
        
        # 設置動作
        settings_action = QAction("設置", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self.show_settings_dialog)
        file_menu.addAction(settings_action)
        
        file_menu.addSeparator()
        
        # 退出動作
        exit_action = QAction("退出", self)
        exit_action.setShortcut(QKeySequence("Ctrl+Q"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 工具菜單
        tools_menu = self.menuBar().addMenu("工具")
        
        # 刷新網卡列表動作
        refresh_interfaces_action = QAction("刷新網卡列表", self)
        refresh_interfaces_action.setShortcut(QKeySequence("F5"))
        refresh_interfaces_action.triggered.connect(self.refresh_interfaces)
        refresh_interfaces_action.setEnabled(False)
        self.refresh_interfaces_action = refresh_interfaces_action
        tools_menu.addAction(refresh_interfaces_action)
        
        # 檢查IP配置動作
        check_ip_action = QAction("檢查IP配置", self)
        check_ip_action.setShortcut(QKeySequence("F6"))
        check_ip_action.triggered.connect(self.check_ip_config)
        check_ip_action.setEnabled(False)
        self.check_ip_action = check_ip_action
        tools_menu.addAction(check_ip_action)
        
        # 幫助菜單
        help_menu = self.menuBar().addMenu("幫助")
        
        # 使用說明動作
        help_action = QAction("使用說明", self)
        help_action.setShortcut(QKeySequence("F1"))
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
        # 關於動作
        about_action = QAction("關於", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
    
    def _create_tool_bar(self):
        """創建工具欄"""
        # 主工具欄
        main_toolbar = QToolBar("主工具欄")
        main_toolbar.setIconSize(QSize(24, 24))
        main_toolbar.setMovable(False)
        self.addToolBar(main_toolbar)
        
        # 連接按鈕
        connect_action = QAction("連接", self)
        connect_action.triggered.connect(self.connect_to_ssh)
        main_toolbar.addAction(connect_action)
        
        # 斷開連接按鈕
        disconnect_action = QAction("斷開", self)
        disconnect_action.triggered.connect(self.disconnect_ssh)
        disconnect_action.setEnabled(False)
        self.toolbar_disconnect_action = disconnect_action
        main_toolbar.addAction(disconnect_action)
        
        main_toolbar.addSeparator()
        
        # 設置按鈕
        settings_action = QAction("設置", self)
        settings_action.triggered.connect(self.show_settings_dialog)
        main_toolbar.addAction(settings_action)
        
        main_toolbar.addSeparator()
        
        # 系統信息按鈕
        system_info_action = QAction("系統信息", self)
        system_info_action.triggered.connect(self.show_system_info)
        system_info_action.setEnabled(False)
        self.toolbar_system_info_action = system_info_action
        main_toolbar.addAction(system_info_action)
        
        # 添加系統信息按鈕到實例變數
        self.system_info_button = QPushButton("系統信息")
        self.system_info_button.clicked.connect(self.show_system_info)
        self.system_info_button.setEnabled(False)
        
        main_toolbar.addSeparator()
    
    def _setup_ssh_tab(self, tab_widget):
        """設置SSH配置選項卡"""
        layout = QVBoxLayout(tab_widget)
        
        # SSH連接配置組
        ssh_group = QGroupBox("SSH 連接配置")
        ssh_layout = QGridLayout(ssh_group)
        
        # 服務器地址
        ssh_layout.addWidget(QLabel("服務器地址:"), 0, 0)
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("例如: 192.168.1.100")
        ssh_layout.addWidget(self.server_input, 0, 1)
        
        # 端口
        ssh_layout.addWidget(QLabel("端口:"), 0, 2)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        ssh_layout.addWidget(self.port_input, 0, 3)
        
        # 用戶名
        ssh_layout.addWidget(QLabel("用戶名:"), 1, 0)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("例如: root")
        ssh_layout.addWidget(self.username_input, 1, 1)
        
        # 密碼
        ssh_layout.addWidget(QLabel("密碼:"), 1, 2)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        ssh_layout.addWidget(self.password_input, 1, 3)
        
        # 密鑰認證選項
        self.use_key_checkbox = QCheckBox("使用密鑰認證")
        ssh_layout.addWidget(self.use_key_checkbox, 2, 0)
        
        # 密鑰路徑
        self.key_path_input = QLineEdit()
        self.key_path_input.setEnabled(False)
        ssh_layout.addWidget(self.key_path_input, 2, 1)
        
        # 瀏覽按鈕
        self.key_browse_button = QPushButton("瀏覽...")
        self.key_browse_button.setEnabled(False)
        ssh_layout.addWidget(self.key_browse_button, 2, 2)
        
        # SSH操作按鈕
        ssh_buttons_layout = QHBoxLayout()
        
        # 連接按鈕
        self.connect_button = QPushButton("連接")
        ssh_buttons_layout.addWidget(self.connect_button)
        
        # 斷開連接按鈕
        self.disconnect_button = QPushButton("斷開連接")
        self.disconnect_button.setEnabled(False)
        ssh_buttons_layout.addWidget(self.disconnect_button)
        
        # 測試連接按鈕
        self.test_button = QPushButton("測試連接")
        ssh_buttons_layout.addWidget(self.test_button)
        
        ssh_layout.addLayout(ssh_buttons_layout, 3, 0, 1, 4)
        
        # 保存密碼選項
        self.save_password_checkbox = QCheckBox("保存密碼")
        ssh_layout.addWidget(self.save_password_checkbox, 4, 0, 1, 2)
        
        # 自動連接選項
        self.auto_connect_checkbox = QCheckBox("啟動時自動連接")
        ssh_layout.addWidget(self.auto_connect_checkbox, 4, 2, 1, 2)
        
        layout.addWidget(ssh_group)
        
        # 最近連接歷史
        history_group = QGroupBox("最近連接")
        history_layout = QVBoxLayout(history_group)
        
        # 最近連接下拉框
        self.recent_connections_combo = QComboBox()
        self.recent_connections_combo.setEditable(False)
        self.recent_connections_combo.setMaxVisibleItems(10)
        history_layout.addWidget(self.recent_connections_combo)
        
        # 歷史操作按鈕
        history_buttons_layout = QHBoxLayout()
        
        # 載入選擇的連接按鈕
        self.load_connection_button = QPushButton("載入選擇的連接")
        history_buttons_layout.addWidget(self.load_connection_button)
        
        # 清除歷史按鈕
        self.clear_history_button = QPushButton("清除歷史")
        history_buttons_layout.addWidget(self.clear_history_button)
        
        history_layout.addLayout(history_buttons_layout)
        
        layout.addWidget(history_group)
        
        # 添加彈性空間
        layout.addStretch()
    
    def _setup_ip_tab(self, tab_widget):
        """設置IP配置選項卡"""
        layout = QVBoxLayout(tab_widget)
        
        # 當前網卡狀態組
        interface_group = QGroupBox("網卡狀態")
        interface_layout = QGridLayout(interface_group)
        
        # 網卡選擇
        interface_layout.addWidget(QLabel("網卡:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.setEnabled(False)
        self.interface_combo.addItem("自動檢測")
        interface_layout.addWidget(self.interface_combo, 0, 1)
        
        # 刷新網卡按鈕
        self.refresh_interfaces_button = QPushButton("刷新網卡列表")
        self.refresh_interfaces_button.setEnabled(False)
        interface_layout.addWidget(self.refresh_interfaces_button, 0, 2)
        
        # 網卡信息按鈕
        self.interface_info_button = QPushButton("網卡詳細信息")
        self.interface_info_button.setEnabled(False)
        interface_layout.addWidget(self.interface_info_button, 0, 3)
        
        # 網卡狀態
        interface_layout.addWidget(QLabel("狀態:"), 1, 0)
        self.interface_status_label = QLabel("未連接")
        interface_layout.addWidget(self.interface_status_label, 1, 1)
        
        # 網卡類型 (DHCP/靜態)
        interface_layout.addWidget(QLabel("配置類型:"), 1, 2)
        self.interface_type_label = QLabel("未知")
        interface_layout.addWidget(self.interface_type_label, 1, 3)
        
        # 功能按鈕佈局
        interface_buttons_layout = QHBoxLayout()
        
        # DHCP轉靜態按鈕
        self.convert_to_static_button = QPushButton("轉換為靜態IP")
        self.convert_to_static_button.setEnabled(False)
        interface_buttons_layout.addWidget(self.convert_to_static_button)
        
        # 清理 Netplan 配置按鈕
        self.clean_netplan_button = QPushButton("清理Netplan配置")
        self.clean_netplan_button.setEnabled(False)
        self.clean_netplan_button.setToolTip("刪除通配符配置（如eth*），保留特定接口配置（如eth0）")
        interface_buttons_layout.addWidget(self.clean_netplan_button)
        
        interface_layout.addLayout(interface_buttons_layout, 2, 0, 1, 4)
        
        layout.addWidget(interface_group)
        
        # DNS設置組
        dns_group = QGroupBox("DNS設置")
        dns_layout = QGridLayout(dns_group)
        
        # 啟用自定義DNS
        self.use_custom_dns_checkbox = QCheckBox("使用自定義DNS")
        self.use_custom_dns_checkbox.setEnabled(False)
        self.use_custom_dns_checkbox.setChecked(True)
        dns_layout.addWidget(self.use_custom_dns_checkbox, 0, 0, 1, 4)
        
        # 主DNS
        dns_layout.addWidget(QLabel("主DNS:"), 1, 0)
        self.primary_dns_input = QLineEdit("8.8.8.8")
        self.primary_dns_input.setPlaceholderText("如: 8.8.8.8")
        dns_layout.addWidget(self.primary_dns_input, 1, 1)
        
        # 次DNS
        dns_layout.addWidget(QLabel("次DNS:"), 1, 2)
        self.secondary_dns_input = QLineEdit("144.144.144.144")
        self.secondary_dns_input.setPlaceholderText("如: 144.144.144.144")
        dns_layout.addWidget(self.secondary_dns_input, 1, 3)
        
        layout.addWidget(dns_group)
        
        # IP配置組
        ip_group = QGroupBox("添加副IP地址")
        ip_layout = QGridLayout(ip_group)
        
        # IP地址輸入
        ip_layout.addWidget(QLabel("IP地址:"), 0, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("例如: 192.168.1.10")
        ip_layout.addWidget(self.ip_input, 0, 1)
        
        # 子網掩碼選擇
        ip_layout.addWidget(QLabel("子網掩碼:"), 0, 2)
        self.netmask_combo = QComboBox()
        self.netmask_combo.addItems([
            "255.255.255.0 (/24)", 
            "255.255.255.128 (/25)",
            "255.255.255.192 (/26)",
            "255.255.255.224 (/27)",
            "255.255.255.240 (/28)",
            "255.255.0.0 (/16)",
            "255.0.0.0 (/8)"
        ])
        ip_layout.addWidget(self.netmask_combo, 0, 3)
        
        # IP操作按鈕
        ip_buttons_layout = QHBoxLayout()
        
        # 添加IP按鈕
        self.add_ip_button = QPushButton("添加IP")
        self.add_ip_button.setEnabled(False)
        ip_buttons_layout.addWidget(self.add_ip_button)
        
        # 檢查IP配置按鈕
        self.check_ip_button = QPushButton("檢查IP配置")
        self.check_ip_button.setEnabled(False)
        ip_buttons_layout.addWidget(self.check_ip_button)
        
        ip_layout.addLayout(ip_buttons_layout, 1, 0, 1, 4)
        
        # 新增刪除IP區域
        ip_layout.addWidget(QLabel("選擇IP:"), 2, 0)
        self.existing_ip_combo = QComboBox()
        self.existing_ip_combo.setEnabled(False)
        ip_layout.addWidget(self.existing_ip_combo, 2, 1)
        
        # 刪除IP按鈕
        self.remove_ip_button = QPushButton("刪除選中IP")
        self.remove_ip_button.setEnabled(False)
        ip_layout.addWidget(self.remove_ip_button, 2, 2, 1, 2)
        
        layout.addWidget(ip_group)
        
        # 批量IP添加組
        batch_group = QGroupBox("批量添加IP")
        batch_layout = QGridLayout(batch_group)
        
        # IP起始地址
        batch_layout.addWidget(QLabel("起始IP:"), 0, 0)
        self.start_ip_input = QLineEdit()
        self.start_ip_input.setPlaceholderText("例如: 192.168.1.10")
        batch_layout.addWidget(self.start_ip_input, 0, 1)
        
        # 結束IP地址
        batch_layout.addWidget(QLabel("結束IP:"), 0, 2)
        self.end_ip_input = QLineEdit()
        self.end_ip_input.setPlaceholderText("例如: 192.168.1.20")
        batch_layout.addWidget(self.end_ip_input, 0, 3)
        
        # 子網掩碼選擇
        batch_layout.addWidget(QLabel("子網掩碼:"), 1, 0)
        self.batch_netmask_combo = QComboBox()
        self.batch_netmask_combo.addItems([
            "255.255.255.0 (/24)", 
            "255.255.255.128 (/25)",
            "255.255.255.192 (/26)",
            "255.255.255.224 (/27)",
            "255.255.255.240 (/28)",
            "255.255.0.0 (/16)",
            "255.0.0.0 (/8)"
        ])
        batch_layout.addWidget(self.batch_netmask_combo, 1, 1)
        
        # 批量操作按鈕
        self.batch_add_button = QPushButton("批量添加")
        self.batch_add_button.setEnabled(False)
        batch_layout.addWidget(self.batch_add_button, 1, 2, 1, 2)
        
        layout.addWidget(batch_group)
        
        # 添加彈性空間
        layout.addStretch()
    
    def _setup_tools_tab(self, tab_widget):
        """設置網絡工具選項卡"""
        layout = QVBoxLayout(tab_widget)
        
        # 網絡診斷工具組
        diagnostic_group = QGroupBox("網絡診斷工具")
        diagnostic_layout = QGridLayout(diagnostic_group)
        
        # Ping工具
        diagnostic_layout.addWidget(QLabel("Ping目標:"), 0, 0)
        self.ping_target_input = QLineEdit()
        self.ping_target_input.setPlaceholderText("例如: 8.8.8.8 或 google.com")
        diagnostic_layout.addWidget(self.ping_target_input, 0, 1)
        
        self.ping_button = QPushButton("Ping")
        self.ping_button.setEnabled(False)
        diagnostic_layout.addWidget(self.ping_button, 0, 2)
        
        # 路由跟蹤工具
        diagnostic_layout.addWidget(QLabel("Traceroute目標:"), 1, 0)
        self.traceroute_target_input = QLineEdit()
        self.traceroute_target_input.setPlaceholderText("例如: 8.8.8.8 或 google.com")
        diagnostic_layout.addWidget(self.traceroute_target_input, 1, 1)
        
        self.traceroute_button = QPushButton("Traceroute")
        self.traceroute_button.setEnabled(False)
        diagnostic_layout.addWidget(self.traceroute_button, 1, 2)
        
        # DNS查詢工具
        diagnostic_layout.addWidget(QLabel("DNS查詢:"), 2, 0)
        self.dns_query_input = QLineEdit()
        self.dns_query_input.setPlaceholderText("例如: google.com")
        diagnostic_layout.addWidget(self.dns_query_input, 2, 1)
        
        self.dns_query_button = QPushButton("DNS查詢")
        self.dns_query_button.setEnabled(False)
        diagnostic_layout.addWidget(self.dns_query_button, 2, 2)
        
        layout.addWidget(diagnostic_group)
        
        # 網絡服務管理組
        service_group = QGroupBox("網絡服務管理")
        service_layout = QGridLayout(service_group)
        
        # 服務選擇
        service_layout.addWidget(QLabel("服務:"), 0, 0)
        self.service_combo = QComboBox()
        self.service_combo.addItems(["網絡服務", "SSH服務", "防火牆", "DHCP客戶端"])
        service_layout.addWidget(self.service_combo, 0, 1)
        
        # 服務操作按鈕
        service_buttons_layout = QHBoxLayout()
        
        self.start_service_button = QPushButton("啟動")
        self.start_service_button.setEnabled(False)
        service_buttons_layout.addWidget(self.start_service_button)
        
        self.stop_service_button = QPushButton("停止")
        self.stop_service_button.setEnabled(False)
        service_buttons_layout.addWidget(self.stop_service_button)
        
        self.restart_service_button = QPushButton("重啟")
        self.restart_service_button.setEnabled(False)
        service_buttons_layout.addWidget(self.restart_service_button)
        
        self.status_service_button = QPushButton("狀態")
        self.status_service_button.setEnabled(False)
        service_buttons_layout.addWidget(self.status_service_button)
        
        service_layout.addLayout(service_buttons_layout, 1, 0, 1, 2)
        
        layout.addWidget(service_group)
        
        # 防火牆管理組
        firewall_group = QGroupBox("防火牆管理")
        firewall_layout = QGridLayout(firewall_group)
        
        # 端口輸入
        firewall_layout.addWidget(QLabel("端口:"), 0, 0)
        self.port_fw_input = QLineEdit()
        self.port_fw_input.setPlaceholderText("例如: 80 或 1000-2000")
        firewall_layout.addWidget(self.port_fw_input, 0, 1)
        
        # 協議選擇
        firewall_layout.addWidget(QLabel("協議:"), 0, 2)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "TCP/UDP"])
        firewall_layout.addWidget(self.protocol_combo, 0, 3)
        
        # 防火牆操作按鈕
        firewall_buttons_layout = QHBoxLayout()
        
        self.open_port_button = QPushButton("開放端口")
        self.open_port_button.setEnabled(False)
        firewall_buttons_layout.addWidget(self.open_port_button)
        
        self.close_port_button = QPushButton("關閉端口")
        self.close_port_button.setEnabled(False)
        firewall_buttons_layout.addWidget(self.close_port_button)
        
        self.check_port_button = QPushButton("檢查端口狀態")
        self.check_port_button.setEnabled(False)
        firewall_buttons_layout.addWidget(self.check_port_button)
        
        firewall_layout.addLayout(firewall_buttons_layout, 1, 0, 1, 4)
        
        layout.addWidget(firewall_group)
        
        # 添加彈性空間
        layout.addStretch()
    
    def _connect_signals(self):
        """連接信號與槽"""
        # SSH連接相關
        self.connect_button.clicked.connect(self.connect_to_ssh)
        self.disconnect_button.clicked.connect(self.disconnect_ssh)
        self.test_button.clicked.connect(self.test_ssh_connection)
        self.use_key_checkbox.toggled.connect(self.toggle_key_auth)
        self.key_browse_button.clicked.connect(self.browse_key_file)
        
        # 歷史連接相關
        self.load_connection_button.clicked.connect(self.load_selected_connection)
        self.clear_history_button.clicked.connect(self.clear_connection_history)
        
        # IP操作相關
        self.add_ip_button.clicked.connect(self.add_ip_address)
        self.check_ip_button.clicked.connect(self.check_ip_config)
        self.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        self.interface_info_button.clicked.connect(self.show_interface_info)
        self.convert_to_static_button.clicked.connect(self.convert_to_static_ip)
        self.clean_netplan_button.clicked.connect(self.clean_netplan_config)
        self.system_info_button.clicked.connect(self.show_system_info)
        self.batch_add_button.clicked.connect(self.batch_add_ip)
        self.remove_ip_button.clicked.connect(self.remove_ip_address)
        self.use_custom_dns_checkbox.toggled.connect(self.toggle_custom_dns)
        
        # 工具選項卡相關
        self.ping_button.clicked.connect(self.run_ping)
        self.traceroute_button.clicked.connect(self.run_traceroute)
        self.dns_query_button.clicked.connect(self.run_dns_query)
        self.start_service_button.clicked.connect(self.start_service)
        self.stop_service_button.clicked.connect(self.stop_service)
        self.restart_service_button.clicked.connect(self.restart_service)
        self.status_service_button.clicked.connect(self.check_service_status)
        self.open_port_button.clicked.connect(self.open_firewall_port)
        self.close_port_button.clicked.connect(self.close_firewall_port)
        self.check_port_button.clicked.connect(self.check_firewall_port)
        
        # 自定義信號
        self.update_log_signal.connect(self.update_log)
        self.update_status_signal.connect(self.update_status)
        self.update_progress_signal.connect(self.update_progress)
        self.ssh_connected_signal.connect(self.on_ssh_connection_changed)
        self.ip_added_signal.connect(self.on_ip_added)
        self.refresh_interfaces_signal.connect(self.on_interfaces_refreshed)
        self.dhcp_status_signal.connect(self.on_dhcp_status_changed)
        
        # 界面控件操作
        self.interface_combo.currentIndexChanged.connect(self.on_interface_changed)
        
        logger.debug("信號槽連接完成")
    
    def _load_saved_config(self):
        """加載保存的配置"""
        config = self.config_manager.load_config()
        
        # 加載SSH連接配置
        if config:
            if 'server' in config:
                self.server_input.setText(config['server'])
            if 'port' in config:
                self.port_input.setValue(int(config['port']))
            if 'username' in config:
                self.username_input.setText(config['username'])
            if 'use_key' in config:
                self.use_key_checkbox.setChecked(config['use_key'])
            if 'key_path' in config:
                self.key_path_input.setText(config['key_path'])
            if 'save_password' in config:
                self.save_password_checkbox.setChecked(config['save_password'])
            if 'auto_connect' in config:
                self.auto_connect_checkbox.setChecked(config['auto_connect'])
            
            # 如果保存了密碼且允許保存
            if 'password' in config and config.get('save_password', False):
                self.password_input.setText(config['password'])
        
        # 加載最近連接歷史
        self._load_connection_history()
        
        # 如果設置了自動連接，嘗試自動連接
        if config.get('auto_connect', False) and self.server_input.text():
            # 使用計時器延遲自動連接，確保界面完全加載
            QTimer.singleShot(500, self.connect_to_ssh)
        
        logger.debug("加載保存的配置完成")
    
    def _save_config(self):
        """保存當前配置"""
        config = {
            'server': self.server_input.text(),
            'port': self.port_input.value(),
            'username': self.username_input.text(),
            'use_key': self.use_key_checkbox.isChecked(),
            'key_path': self.key_path_input.text(),
            'save_password': self.save_password_checkbox.isChecked(),
            'auto_connect': self.auto_connect_checkbox.isChecked()
        }
        
        # 只有當用戶允許保存密碼時才保存
        if self.save_password_checkbox.isChecked():
            config['password'] = self.password_input.text()
        elif 'password' in self.config_manager.config:
            # 如果用戶不再允許保存密碼，從配置中移除
            del self.config_manager.config['password']
        
        self.config_manager.save_config(config)
        logger.debug("保存當前配置完成")
    
    def _load_connection_history(self):
        """加載連接歷史"""
        recent_connections = self.config_manager.get_recent_connections()
        
        # 清空下拉框
        self.recent_connections_combo.clear()
        
        # 添加連接歷史
        for conn in recent_connections:
            display_text = f"{conn['username']}@{conn['server']}:{conn['port']}"
            self.recent_connections_combo.addItem(display_text, conn)
        
        logger.debug(f"加載了 {len(recent_connections)} 條連接歷史")
    
    def _add_to_connection_history(self, connection_info):
        """添加連接信息到歷史"""
        # 添加到配置管理器
        self.config_manager.add_recent_connection(connection_info)
        
        # 重新加載連接歷史
        self._load_connection_history()
    
    @pyqtSlot()
    def toggle_key_auth(self):
        """切換密鑰認證模式"""
        use_key = self.use_key_checkbox.isChecked()
        self.key_path_input.setEnabled(use_key)
        self.key_browse_button.setEnabled(use_key)
        self.password_input.setEnabled(not use_key)
        self.save_password_checkbox.setEnabled(not use_key)
    
    @pyqtSlot()
    def browse_key_file(self):
        """瀏覽選擇SSH密鑰文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "選擇SSH密鑰文件", "", "所有文件 (*)"
        )
        if file_path:
            self.key_path_input.setText(file_path)
    
    @pyqtSlot()
    def connect_to_ssh(self):
        """連接到SSH服務器"""
        # 獲取連接參數
        server = self.server_input.text()
        port = self.port_input.value()
        username = self.username_input.text()
        
        # 驗證必要參數
        if not server or not username:
            QMessageBox.warning(self, "輸入錯誤", "服務器地址和用戶名不能為空")
            return
        
        # 驗證服務器地址格式
        if not is_valid_hostname(server) and not is_valid_ip(server):
            QMessageBox.warning(self, "輸入錯誤", "服務器地址格式不正確")
            return
        
        # 驗證端口格式
        if not is_valid_port(port):
            QMessageBox.warning(self, "輸入錯誤", "端口必須在1-65535範圍內")
            return
        
        # 禁用連接按鈕，避免重複點擊
        self.connect_button.setEnabled(False)
        self.test_button.setEnabled(False)
        self.update_status_signal.emit("正在連接到SSH服務器...")
        self.update_progress_signal.emit(10)
        
        # 保存當前配置
        self._save_config()
        
        # 保存連接信息
        self.current_server_info = {
            'server': server,
            'port': port,
            'username': username,
            'use_key': self.use_key_checkbox.isChecked()
        }
        
        # 在後台線程中執行SSH連接
        def connect_thread():
            try:
                # 創建SSH客戶端
                self.ssh_client = SSHClient()
                
                # 根據認證方式選擇連接參數
                if self.use_key_checkbox.isChecked():
                    key_path = self.key_path_input.text()
                    if not key_path:
                        raise SSHConnectionError("密鑰文件路徑不能為空")
                    
                    self.update_log_signal.emit(f"使用密鑰認證連接到 {server}:{port}")
                    self.ssh_client.connect_with_key(
                        server, port, username, key_path
                    )
                else:
                    password = self.password_input.text()
                    if not password:
                        raise SSHConnectionError("密碼不能為空")
                    
                    self.update_log_signal.emit(f"使用密碼認證連接到 {server}:{port}")
                    self.ssh_client.connect_with_password(
                        server, port, username, password
                    )
                
                # 獲取服務器信息
                server_info = self.ssh_client.get_server_info()
                
                # 更新連接信息
                connection_info = {
                    'server': server,
                    'port': port,
                    'username': username,
                    'use_key': self.use_key_checkbox.isChecked()
                }
                
                if self.use_key_checkbox.isChecked():
                    connection_info['key_path'] = self.key_path_input.text()
                elif self.save_password_checkbox.isChecked():
                    connection_info['password'] = self.password_input.text()
                
                # 添加到連接歷史
                self._add_to_connection_history(connection_info)
                
                # 通知UI連接成功
                self.update_log_signal.emit(f"成功連接到 {username}@{server}:{port}")
                self.update_progress_signal.emit(100)
                self.ssh_connected_signal.emit(True)
                
            except SSHConnectionError as e:
                self.update_log_signal.emit(f"SSH連接失敗: {str(e)}")
                self.update_status_signal.emit("SSH連接失敗")
                self.update_progress_signal.emit(0)
                self.ssh_connected_signal.emit(False)
                
                # 在主線程中顯示錯誤對話框
                self.show_error_dialog("SSH連接錯誤", str(e))
            finally:
                # 重新啟用連接按鈕
                self.connect_button.setEnabled(True)
                self.test_button.setEnabled(True)
        
        # 啟動連接線程
        threading.Thread(target=connect_thread, daemon=True).start()
    
    @pyqtSlot()
    def disconnect_ssh(self):
        """斷開SSH連接"""
        if self.ssh_client:
            self.update_status_signal.emit("正在斷開SSH連接...")
            
            def disconnect_thread():
                try:
                    self.ssh_client.disconnect()
                    self.ssh_client = None
                    self.ip_manager = None
                    self.update_log_signal.emit("已斷開SSH連接")
                    self.ssh_connected_signal.emit(False)
                    
                    # 清空界面數據
                    self.interface_combo.clear()
                    self.interface_combo.addItem("自動檢測")
                    self.interface_status_label.setText("未連接")
                    self.interface_type_label.setText("未知")
                    
                except Exception as e:
                    self.update_log_signal.emit(f"斷開連接時發生錯誤: {str(e)}")
            
            threading.Thread(target=disconnect_thread, daemon=True).start()
    
    @pyqtSlot()
    def test_ssh_connection(self):
        """測試SSH連接"""
        # 獲取連接參數
        server = self.server_input.text()
        port = self.port_input.value()
        username = self.username_input.text()
        
        # 驗證必要參數
        if not server or not username:
            QMessageBox.warning(self, "輸入錯誤", "服務器地址和用戶名不能為空")
            return
        
        # 驗證服務器地址格式
        if not is_valid_hostname(server) and not is_valid_ip(server):
            QMessageBox.warning(self, "輸入錯誤", "服務器地址格式不正確")
            return
        
        # 禁用測試按鈕，避免重複點擊
        self.test_button.setEnabled(False)
        self.update_status_signal.emit("正在測試SSH連接...")
        self.update_progress_signal.emit(10)
        
        # 在後台線程中執行SSH連接測試
        def test_thread():
            ssh_client = None
            try:
                # 創建SSH客戶端
                ssh_client = SSHClient()
                
                # 根據認證方式選擇連接參數
                if self.use_key_checkbox.isChecked():
                    key_path = self.key_path_input.text()
                    if not key_path:
                        raise SSHConnectionError("密鑰文件路徑不能為空")
                    
                    self.update_log_signal.emit(f"測試連接: 使用密鑰認證連接到 {server}:{port}")
                    ssh_client.connect_with_key(
                        server, port, username, key_path
                    )
                else:
                    password = self.password_input.text()
                    if not password:
                        raise SSHConnectionError("密碼不能為空")
                    
                    self.update_log_signal.emit(f"測試連接: 使用密碼認證連接到 {server}:{port}")
                    ssh_client.connect_with_password(
                        server, port, username, password
                    )
                
                # 執行簡單的echo命令，檢查連接是否正常
                exit_code, stdout, stderr = ssh_client.execute_command('echo "Connection test successful"')
                
                if exit_code == 0:
                    self.update_log_signal.emit("SSH連接測試成功")
                    self.update_status_signal.emit("連接測試成功")
                    self.update_progress_signal.emit(100)
                    
                    # 顯示成功消息
                    self.show_message_dialog("連接測試", "SSH連接測試成功")
                else:
                    self.update_log_signal.emit(f"SSH連接測試失敗: {stderr}")
                    self.update_status_signal.emit("連接測試失敗")
                    self.update_progress_signal.emit(0)
                    
                    # 顯示失敗消息
                    self.show_error_dialog("連接測試", f"SSH連接測試失敗:\n{stderr}")
                
            except SSHConnectionError as e:
                self.update_log_signal.emit(f"連接測試失敗: {str(e)}")
                self.update_status_signal.emit("連接測試失敗")
                self.update_progress_signal.emit(0)
                
                # 顯示錯誤消息
                self.show_error_dialog("連接測試", f"SSH連接測試失敗:\n{str(e)}")
            finally:
                # 斷開測試連接
                if ssh_client and ssh_client.is_connected():
                    ssh_client.disconnect()
                
                # 重新啟用測試按鈕
                self.test_button.setEnabled(True)
        
        # 啟動測試線程
        threading.Thread(target=test_thread, daemon=True).start()
    
    @pyqtSlot()
    def load_selected_connection(self):
        """載入選擇的歷史連接"""
        # 獲取當前選中的連接
        current_index = self.recent_connections_combo.currentIndex()
        if current_index < 0:
            return
        
        # 獲取連接信息
        connection_data = self.recent_connections_combo.itemData(current_index)
        if not connection_data:
            return
        
        # 填充連接表單
        self.server_input.setText(connection_data['server'])
        self.port_input.setValue(int(connection_data['port']))
        self.username_input.setText(connection_data['username'])
        self.use_key_checkbox.setChecked(connection_data['use_key'])
        
        if connection_data['use_key'] and 'key_path' in connection_data:
            self.key_path_input.setText(connection_data['key_path'])
        
        # 如果保存了密碼
        if 'password' in connection_data:
            self.password_input.setText(connection_data['password'])
        
        self.update_log_signal.emit(f"已載入連接設置: {self.username_input.text()}@{self.server_input.text()}:{self.port_input.value()}")
    
    @pyqtSlot()
    def clear_connection_history(self):
        """清除連接歷史"""
        reply = QMessageBox.question(
            self, "確認操作", 
            "確定要清除所有連接歷史嗎？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.config_manager.clear_recent_connections()
            self.recent_connections_combo.clear()
            self.update_log_signal.emit("已清除連接歷史")
    
    def refresh_interfaces(self):
        """刷新網卡列表"""
        if not self.is_connected or not self.ssh_client:
            return
        
        self.update_status_signal.emit("正在刷新網卡列表...")
        self.update_progress_signal.emit(10)
        self.refresh_interfaces_button.setEnabled(False)
        
        def refresh_thread():
            try:
                if not self.ip_manager:
                    self.ip_manager = IPManager(self.ssh_client)
                
                # 獲取網卡列表
                interfaces = self.ip_manager.get_interfaces()
                
                # 獲取默認網卡
                default_interface = self.ip_manager.get_default_interface()
                
                # 收集網卡詳細信息和DHCP狀態
                interfaces_info = []
                dhcp_interfaces = set()
                
                for interface in interfaces:
                    try:
                        # 獲取網卡詳細信息
                        info = self.ip_manager.get_full_interface_info(interface)
                        interfaces_info.append((interface, info))
                        
                        # 檢查是否為DHCP配置
                        network_config = self.ip_manager.analyze_network_config(interface)
                        if network_config["is_dhcp"]:
                            dhcp_interfaces.add(interface)
                            
                    except Exception as e:
                        logger.error(f"獲取網卡 {interface} 信息時發生錯誤: {str(e)}")
                
                # 在界面中更新所有收集的信息
                self.refresh_interfaces_signal.emit(interfaces)
                self.interface_details = dict(interfaces_info)
                self.dhcp_interfaces = dhcp_interfaces
                
                # 更新IP下拉框
                self.refresh_ip_list(default_interface if default_interface else interfaces[0] if interfaces else None)
                
                self.update_status_signal.emit("網卡列表刷新完成")
                self.update_progress_signal.emit(100)
                
            except Exception as e:
                logger.error(f"刷新網卡列表時發生錯誤: {str(e)}")
                self.update_log_signal.emit(f"刷新網卡列表時發生錯誤: {str(e)}")
                self.update_status_signal.emit("網卡列表刷新失敗")
                self.update_progress_signal.emit(0)
                
            finally:
                # 在主線程中啟用刷新按鈕
                QMetaObject.invokeMethod(
                    self.refresh_interfaces_button,
                    "setEnabled",
                    Qt.QueuedConnection,
                    Q_ARG(bool, True)
                )
        
        # 在後台線程中執行刷新操作
        threading.Thread(target=refresh_thread, daemon=True).start()
    
    def refresh_ip_list(self, interface=None):
        """刷新指定網卡的IP地址列表"""
        if not self.is_connected or not self.ssh_client:
            return
        
        if interface is None:
            interface = self.get_selected_interface()
            if not interface:
                # 嘗試從界面獲取選中的網卡
                idx = self.interface_combo.currentIndex()
                if idx > 0:
                    interface = self.interface_combo.itemText(idx)
                else:
                    # 嘗試使用默認網卡
                    try:
                        if self.ip_manager:
                            interface = self.ip_manager.get_default_interface()
                        else:
                            self.ip_manager = IPManager(self.ssh_client)
                            interface = self.ip_manager.get_default_interface()
                    except:
                        self.update_log_signal.emit("無法獲取默認網卡")
                        return
        
        if not interface:
            self.update_log_signal.emit("未選擇網卡，無法刷新IP列表")
            return
        
        self.update_log_signal.emit(f"正在獲取網卡 {interface} 的IP地址列表...")
        
        def refresh_ip_thread():
            try:
                # 初始化IP管理器（如果尚未創建）
                if not self.ip_manager:
                    self.ip_manager = IPManager(self.ssh_client)
                
                # 直接使用ip addr命令獲取IP信息
                exit_code, stdout, stderr = self.ssh_client.execute_command(f"ip addr show {interface}")
                
                if exit_code != 0:
                    logger.error(f"獲取網卡信息失敗: {stderr}")
                    self.update_log_signal.emit(f"獲取網卡 {interface} 信息失敗")
                    return
                
                self.update_log_signal.emit(f"網卡 {interface} 的IP配置:\n{stdout}")
                
                # 解析IP地址
                ip_addresses = []
                import re
                # 匹配IPv4地址
                pattern = r"inet\s+([0-9.]+)\/(\d+)"
                matches = re.findall(pattern, stdout)
                
                for match in matches:
                    ip, prefix = match
                    ip_addresses.append(f"{ip}/{prefix}")
                
                # 在主線程中更新下拉框
                def update_combo():
                    try:
                        self.existing_ip_combo.clear()
                        if not ip_addresses:
                            self.existing_ip_combo.addItem("無IP地址")
                            self.remove_ip_button.setEnabled(False)
                            return
                        
                        # 添加所有IP
                        for ip in ip_addresses:
                            self.existing_ip_combo.addItem(ip)
                        
                        # 啟用刪除按鈕（如果有多個IP）
                        self.remove_ip_button.setEnabled(len(ip_addresses) > 1)
                    except Exception as e:
                        logger.error(f"更新IP下拉框失敗: {e}")
                
                # 直接在主線程中執行UI更新
                QMetaObject.invokeMethod(
                    self,
                    "run_in_main_thread",
                    Qt.QueuedConnection,
                    Q_ARG(object, update_combo)
                )
                
            except Exception as e:
                logger.error(f"刷新IP列表時發生錯誤: {str(e)}")
                self.update_log_signal.emit(f"刷新IP列表時發生錯誤: {str(e)}")
        
        # 在後台線程中執行刷新操作
        threading.Thread(target=refresh_ip_thread, daemon=True).start()
    
    @pyqtSlot(object)
    def run_in_main_thread(self, function):
        """在主線程中執行函數"""
        function()
    
    @pyqtSlot()
    def remove_ip_address(self):
        """刪除選定的IP地址"""
        if not self.is_connected or not self.ssh_client or not self.ip_manager:
            return
        
        # 獲取選定的IP地址
        selected_ip = self.existing_ip_combo.currentText()
        if not selected_ip or selected_ip == "無IP地址":
            self.update_log_signal.emit("請選擇要刪除的IP地址")
            return
        
        # 獲取選定的網卡
        interface = self.get_selected_interface()
        if not interface:
            self.update_log_signal.emit("請選擇網卡")
            return
        
        # 確認刪除
        confirm = QMessageBox.question(
            self,
            "確認刪除",
            f"確定要從網卡 {interface} 刪除IP地址 {selected_ip} 嗎？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
        
        # 禁用刪除按鈕，避免重複操作
        self.remove_ip_button.setEnabled(False)
        self.update_status_signal.emit(f"正在刪除IP地址 {selected_ip}...")
        self.update_progress_signal.emit(10)
        
        def remove_ip_thread():
            try:
                # 嘗試刪除IP地址
                self.update_log_signal.emit(f"正在從網卡 {interface} 刪除IP地址 {selected_ip}...")
                
                # 如果IP地址格式不包含CIDR，添加默認的/24
                ip_to_remove = selected_ip
                if "/" not in ip_to_remove:
                    ip_to_remove = f"{ip_to_remove}/24"
                
                self.ip_manager.remove_ip_address(ip_to_remove, interface)
                
                self.update_log_signal.emit(f"成功從網卡 {interface} 刪除IP地址 {selected_ip}")
                self.update_status_signal.emit("IP地址刪除成功")
                self.update_progress_signal.emit(100)
                
                # 刷新IP列表
                self.refresh_ip_list(interface)
                
            except Exception as e:
                logger.error(f"刪除IP地址時發生錯誤: {str(e)}")
                self.update_log_signal.emit(f"刪除IP地址時發生錯誤: {str(e)}")
                self.update_status_signal.emit("IP地址刪除失敗")
                self.update_progress_signal.emit(0)
                self.show_error_dialog("刪除失敗", f"刪除IP地址時發生錯誤: {str(e)}")
                
            finally:
                # 在主線程中啟用刪除按鈕
                QMetaObject.invokeMethod(
                    self.remove_ip_button,
                    "setEnabled",
                    Qt.QueuedConnection,
                    Q_ARG(bool, True)
                )
        
        # 在後台線程中執行刪除操作
        threading.Thread(target=remove_ip_thread, daemon=True).start()
    
    @pyqtSlot(list)
    def on_interfaces_refreshed(self, interfaces):
        """
        當網卡列表刷新時更新界面並正確反映配置類型
        
        參數:
            interfaces (list): 網卡列表
        """
        # 保存當前選擇的網卡索引
        current_index = self.interface_combo.currentIndex()
        current_interface = None
        if current_index > 0:
            current_interface = self.interface_combo.itemData(current_index)
        
        # 清空下拉框
        self.interface_combo.clear()
        
        # 添加自動檢測選項
        self.interface_combo.addItem("自動檢測", None)
        
        # 恢復之前選擇的網卡索引
        select_index = 0
        
        # 添加網卡列表
        for i, interface in enumerate(interfaces):
            self.interface_combo.addItem(interface, interface)
            
            # 如果是之前選擇的網卡，記錄索引
            if interface == current_interface:
                select_index = i + 1  # +1是因為第一項是"自動檢測"
                
            # 獲取並存儲網卡詳細信息
            try:
                if interface not in self.interface_details:
                    interface_config = self.ip_manager.get_full_interface_info(interface)
                    self.interface_details[interface] = interface_config
                
                # 分析網卡配置類型
                network_config = self.ip_manager.analyze_network_config(interface)
                
                # 判斷配置類型
                is_dhcp = network_config.get("is_dhcp", False)
                has_dhcp_process = network_config.get("dhcp_active", False)
                has_static_config = (network_config.get("config_type") == "interfaces.d" or 
                                    network_config.get("config_type") == "interfaces") and not is_dhcp
                
                # 更新DHCP接口集合
                if is_dhcp and not has_static_config:
                    self.dhcp_interfaces.add(interface)
                elif has_static_config:
                    # 有靜態配置的情況下，從DHCP集合中移除
                    if interface in self.dhcp_interfaces:
                        self.dhcp_interfaces.discard(interface)
            except Exception as e:
                logger.error(f"獲取接口 {interface} 信息時發生錯誤: {str(e)}")
        
        # 設置選中項
        self.interface_combo.setCurrentIndex(select_index)
        
        # 更新UI狀態
        self.interface_combo.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)
        self.interface_info_button.setEnabled(len(interfaces) > 0)
        self.add_ip_button.setEnabled(len(interfaces) > 0)
        self.check_ip_button.setEnabled(len(interfaces) > 0)
        self.remove_ip_button.setEnabled(len(interfaces) > 0)
        self.existing_ip_combo.setEnabled(len(interfaces) > 0)
        
        # 保存網卡列表
        self.interfaces_list = interfaces
        
        # 刷新IP列表（為當前選擇的網卡）
        if select_index > 0:
            self.refresh_ip_list(self.interface_combo.itemData(select_index))
            
        # 更新當前選中的網卡狀態顯示
        if select_index > 0:
            self.update_interface_status_display(self.interface_combo.itemData(select_index))
        
    @pyqtSlot(int)
    def on_interface_changed(self, index):
        """
        當選擇的網卡改變時更新界面狀態顯示
        
        參數:
            index (int): 選擇的索引
        """
        if index <= 0:
            # 選擇了"自動檢測"，禁用相關按鈕
            self.interface_info_button.setEnabled(False)
            self.convert_to_static_button.setEnabled(False)
            self.interface_status_label.setText("未選擇")
            self.interface_type_label.setText("未知")
            return
        
        # 獲取選中的網卡
        interface = self.interface_combo.itemData(index)
        
        if not interface:
            return
        
        # 更新界面顯示
        self.update_interface_status_display(interface)
        
        # 刷新該網卡的IP列表
        self.refresh_ip_list(interface)

    def update_interface_status_display(self, interface):
        """
        更新指定網卡的狀態顯示
        
        參數:
            interface (str): 網卡名稱
        """
        # 檢查接口是否存在
        if not self.ip_manager or not self.ip_manager._interface_exists(interface):
            self.interface_status_label.setText("未知")
            self.interface_type_label.setText("未知")
            self.convert_to_static_button.setEnabled(False)
            self.interface_info_button.setEnabled(False)
            return
        
        # 獲取網卡配置信息
        try:
            network_config = self.ip_manager.analyze_network_config(interface)
            
            # 判斷配置類型
            is_dhcp = network_config.get("is_dhcp", False)
            has_dhcp_process = network_config.get("dhcp_active", False)
            has_static_config = (network_config.get("config_type") == "interfaces.d" or 
                                network_config.get("config_type") == "interfaces") and not is_dhcp
            
            # 設置界面狀態
            self.interface_status_label.setText("正常")
            
            # 設置配置類型顯示
            if has_static_config:
                if has_dhcp_process:
                    self.interface_type_label.setText("靜態IP (DHCP活躍)")
                else:
                    self.interface_type_label.setText("靜態IP")
                # 只有仍有DHCP進程在運行時才啟用轉換按鈕
                self.convert_to_static_button.setEnabled(has_dhcp_process)
            elif is_dhcp or has_dhcp_process:
                self.interface_type_label.setText("DHCP")
                self.convert_to_static_button.setEnabled(True)
            else:
                self.interface_type_label.setText("未知")
                self.convert_to_static_button.setEnabled(False)
            
            # 更新DHCP接口集合
            if is_dhcp and not has_static_config:
                self.dhcp_interfaces.add(interface)
            elif has_static_config:
                if interface in self.dhcp_interfaces:
                    self.dhcp_interfaces.discard(interface)
            
            # 啟用詳細信息按鈕
            self.interface_info_button.setEnabled(True)
            
        except Exception as e:
            logger.error(f"更新接口 {interface} 狀態顯示時發生錯誤: {str(e)}")
            self.interface_status_label.setText("錯誤")
            self.interface_type_label.setText("未知")
            self.convert_to_static_button.setEnabled(False)
    
    @pyqtSlot(bool, dict)
    def on_dhcp_status_changed(self, is_dhcp, config):
        """
        處理DHCP狀態變化事件
        
        參數:
            is_dhcp (bool): 是否為DHCP配置
            config (dict): 網卡配置信息
        """
        # 更新界面顯示
        iface = config.get("interface", "")
        if not iface:
            return
        
        # 更新dhcp_interfaces集合
        if is_dhcp:
            self.dhcp_interfaces.add(iface)
        elif iface in self.dhcp_interfaces:
            self.dhcp_interfaces.remove(iface)
        
        # 更新界面顯示
        current_iface = self.get_selected_interface()
        if current_iface == iface:
            self.interface_type_label.setText("DHCP" if is_dhcp else "靜態IP")
            self.convert_to_static_button.setEnabled(is_dhcp)
    
    @pyqtSlot()
    def show_interface_info(self):
        """顯示網卡詳細信息對話框"""
        if not self.ip_manager:
            return
        
        # 獲取選中的網卡
        iface = self.get_selected_interface()
        if not iface:
            self.show_error_dialog("錯誤", "請先選擇一個網卡")
            return
        
        try:
            # 獲取網卡詳細信息
            config = self.ip_manager.get_full_interface_info(iface)
            
            # 創建並顯示網卡信息對話框
            dialog = NetworkInterfaceDialog(self, iface, config)
            dialog.exec_()
            
        except Exception as e:
            self.show_error_dialog("獲取網卡信息錯誤", str(e))
    
    @pyqtSlot()
    def convert_to_static_ip(self):
        """將DHCP網卡轉換為靜態IP配置"""
        # 獲取選中的網卡
        interface = self.get_selected_interface()
        if not interface:
            self.show_message_dialog("提示", "請先選擇網卡")
            return
            
        # 檢查是否為DHCP配置
        if interface not in self.dhcp_interfaces:
            self.show_message_dialog("提示", "選中的網卡不是DHCP配置或狀態未知")
            return
            
        # 詢問用戶是否確定
        confirm = QMessageBox.question(
            self,
            "確認操作",
            f"確定要將網卡 {interface} 的配置從DHCP轉換為靜態IP嗎？\n\n這將會保留當前IP地址和網絡設置。\n本操作不可逆，請確保您了解這樣做的後果。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
            
        # 獲取網卡詳細信息
        if interface not in self.interface_details:
            self.update_log_signal.emit(f"獲取網卡 {interface} 的詳細信息...")
            self.interface_details[interface] = self.ip_manager.get_full_interface_info(interface)
            
        details = self.interface_details[interface]
        
        # 獲取當前IP配置
        ip_address = details.get("ip_address", "")
        netmask = details.get("netmask", "")
        cidr = details.get("cidr", 24)
        gateway = details.get("gateway", "")
        
        # 獲取DNS服務器
        dns_servers = []
        if self.use_custom_dns_checkbox.isChecked():
            primary_dns = self.primary_dns_input.text().strip()
            secondary_dns = self.secondary_dns_input.text().strip()
            
            if primary_dns and is_valid_ip(primary_dns):
                dns_servers.append(primary_dns)
            if secondary_dns and is_valid_ip(secondary_dns):
                dns_servers.append(secondary_dns)
        else:
            dns_servers = details.get("dns_servers", [])
            
        # 顯示將要設置的配置
        settings_message = (
            f"即將應用以下靜態IP配置:\n\n"
            f"IP地址: {ip_address}\n"
            f"子網掩碼: {netmask} (/{cidr})\n"
            f"默認網關: {gateway}\n"
            f"DNS服務器: {', '.join(dns_servers) if dns_servers else '無變更'}\n\n"
            f"注意: 此操作將同時清理Netplan配置（如果適用）\n"
            f"確定要繼續嗎?"
        )
        
        settings_confirm = QMessageBox.question(
            self,
            "確認配置",
            settings_message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if settings_confirm != QMessageBox.Yes:
            return
            
        # 禁用按鈕，避免重複操作
        self.convert_to_static_button.setEnabled(False)
        self.update_status_signal.emit(f"正在將網卡 {interface} 從DHCP轉換為靜態IP...")
        self.update_progress_signal.emit(10)
        
        # 在後台線程中執行轉換操作
        def convert_thread():
            try:
                # 執行轉換
                success = self.ip_manager.convert_dhcp_to_static(
                    interface, ip_address, netmask, gateway, dns_servers
                )
                
                self.update_progress_signal.emit(75)
                
                if success:
                    self.update_log_signal.emit(f"成功將網卡 {interface} 從DHCP轉換為靜態IP")
                    
                    # 自動執行清理Netplan配置
                    if self.ip_manager._os_type == "netplan":
                        self.update_log_signal.emit(f"正在自動清理網卡 {interface} 的Netplan配置...")
                        self.update_progress_signal.emit(80)
                        
                        clean_result = self.ip_manager.clean_netplan_config(interface)
                        
                        if clean_result:
                            self.update_log_signal.emit(f"成功清理網卡 {interface} 的Netplan配置")
                        else:
                            self.update_log_signal.emit(f"清理網卡 {interface} 的Netplan配置失敗")
                    
                    # 更新界面
                    self.dhcp_interfaces.discard(interface)
                    self.update_status_signal.emit("轉換為靜態IP完成")
                    
                    # 刷新界面
                    self.refresh_interfaces()
                    
                    # 顯示成功信息
                    self.run_in_main_thread(
                        lambda: self.show_message_dialog("操作成功", "成功將網卡從DHCP轉換為靜態IP配置")
                    )
                else:
                    self.update_log_signal.emit(f"將網卡 {interface} 從DHCP轉換為靜態IP失敗")
                    self.update_status_signal.emit("轉換為靜態IP失敗")
                    
                    # 顯示失敗信息
                    self.run_in_main_thread(
                        lambda: self.show_error_dialog("操作失敗", "轉換為靜態IP失敗，請查看日誌了解詳情")
                    )
                
            except Exception as e:
                logger.error(f"轉換為靜態IP時發生錯誤: {str(e)}")
                self.update_log_signal.emit(f"錯誤: {str(e)}")
                self.update_status_signal.emit("轉換為靜態IP失敗")
                
                # 顯示錯誤信息
                self.run_in_main_thread(
                    lambda: self.show_error_dialog("轉換錯誤", str(e))
                )
            
            finally:
                # 更新進度條
                self.update_progress_signal.emit(100)
                # 短暫停頓後重置進度條
                time.sleep(1)
                self.update_progress_signal.emit(0)
                
                # 重新啟用按鈕
                self.run_in_main_thread(lambda: self.convert_to_static_button.setEnabled(True))
                
        # 啟動轉換線程
        threading.Thread(target=convert_thread, daemon=True).start()
    
    @pyqtSlot()
    def add_ip_address(self):
        """添加IP地址到網卡"""
        if not self.is_connected or not self.ip_manager:
            return
        
        # 獲取IP參數
        ip_address = self.ip_input.text()
        netmask_text = self.netmask_combo.currentText()
        
        # 提取CIDR格式的網絡掩碼
        import re
        cidr_match = re.search(r"\(/(\d+)\)", netmask_text)
        if cidr_match:
            cidr = cidr_match.group(1)
        else:
            cidr = "24"  # 默認使用/24
        
        # 驗證IP地址格式
        if not is_valid_ip(ip_address):
            QMessageBox.warning(self, "輸入錯誤", "IP地址格式不正確")
            return
        
        # 獲取選中的網卡
        interface = self.get_selected_interface()
        
        # 禁用添加按鈕，避免重複點擊
        self.add_ip_button.setEnabled(False)
        self.update_status_signal.emit("正在添加IP地址...")
        self.update_progress_signal.emit(10)
        
        def add_ip_thread():
            try:
                ip_with_cidr = f"{ip_address}/{cidr}"
                self.update_log_signal.emit(f"正在添加IP: {ip_with_cidr} 到網卡 {interface or '(自動檢測)'}")
                
                # 執行IP添加操作
                result = self.ip_manager.add_ip_address(ip_with_cidr, interface)
                
                # 更新界面
                self.update_progress_signal.emit(100)
                self.update_log_signal.emit(f"成功添加IP: {ip_with_cidr}")
                self.update_status_signal.emit("IP添加成功")
                
                # 發送IP添加成功信號
                self.ip_added_signal.emit(True, ip_with_cidr)
                
                # 清空IP輸入框
                self.ip_input.clear()
                
            except IPConfigError as e:
                self.update_log_signal.emit(f"添加IP失敗: {str(e)}")
                self.update_status_signal.emit("IP添加失敗")
                self.update_progress_signal.emit(0)
                
                # 發送IP添加失敗信號
                self.ip_added_signal.emit(False, str(e))
                
                # 在主線程中顯示錯誤對話框
                self.show_error_dialog("IP配置錯誤", str(e))
            finally:
                # 重新啟用添加按鈕
                self.add_ip_button.setEnabled(True)
        
        # 啟動IP添加線程
        threading.Thread(target=add_ip_thread, daemon=True).start()
    
    @pyqtSlot()
    def batch_add_ip(self):
        """批量添加IP地址"""
        # 檢查是否已連接
        if not self.is_connected or not self.ip_manager:
            return
            
        # 獲取參數
        start_ip = self.start_ip_input.text()
        end_ip = self.end_ip_input.text()
        netmask_text = self.batch_netmask_combo.currentText()
        
        # 從子網掩碼文本中提取CIDR
        cidr = int(re.search(r'/(\d+)', netmask_text).group(1))
        
        # 參數檢查
        if not start_ip:
            QMessageBox.warning(self, "輸入錯誤", "請輸入起始IP地址")
            return
            
        if not end_ip:
            QMessageBox.warning(self, "輸入錯誤", "請輸入結束IP地址")
            return
        
        if not is_valid_ip(start_ip):
            QMessageBox.warning(self, "輸入錯誤", "起始IP地址格式不正確")
            return
        
        if not is_valid_ip(end_ip):
            QMessageBox.warning(self, "輸入錯誤", "結束IP地址格式不正確")
            return
        
        # 檢查IP範圍
        try:
            import ipaddress
            start_ip_obj = ipaddress.IPv4Address(start_ip)
            end_ip_obj = ipaddress.IPv4Address(end_ip)
            
            if end_ip_obj < start_ip_obj:
                QMessageBox.warning(self, "輸入錯誤", "結束IP必須大於或等於起始IP")
                return
            
            # 計算IP數量
            ip_count = int(end_ip_obj) - int(start_ip_obj) + 1
            
            # 檢查IP數量是否合理
            if ip_count > 100:
                result = QMessageBox.question(
                    self, 
                    "確認操作", 
                    f"您將添加 {ip_count} 個IP地址，數量較多可能需要較長時間。是否繼續？",
                    QMessageBox.Yes | QMessageBox.No
                )
                if result != QMessageBox.Yes:
                    return
        except Exception as e:
            QMessageBox.warning(self, "輸入錯誤", f"IP地址處理錯誤: {str(e)}")
            return
        
        # 獲取選中的網卡
        interface = self.get_selected_interface()
        
        # 確認操作
        msg = (
            f"即將批量添加IP地址:\n"
            f"起始IP: {start_ip}\n"
            f"結束IP: {end_ip}\n"
            f"IP數量: {ip_count}\n"
            f"子網掩碼: {netmask_text}\n"
            f"網卡: {interface or '(自動檢測)'}\n\n"
            f"確認繼續操作?"
        )
        
        confirm = QMessageBox.question(
            self, "確認操作", msg, QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            # 禁用批量添加按鈕，避免重複操作
            self.batch_add_button.setEnabled(False)
            self.update_status_signal.emit("正在批量添加IP地址...")
            self.update_progress_signal.emit(10)
            
            # 在後台線程中執行IP添加操作
            def batch_add_thread():
                try:
                    import ipaddress
                    start_ip_obj = ipaddress.IPv4Address(start_ip)
                    end_ip_obj = ipaddress.IPv4Address(end_ip)
                    
                    # 記錄成功和失敗的IP
                    success_ips = []
                    failed_ips = []
                    
                    # 逐個添加IP
                    current_ip_obj = start_ip_obj
                    progress_count = 0
                    
                    while current_ip_obj <= end_ip_obj:
                        try:
                            # 當前IP
                            current_ip = str(current_ip_obj)
                            ip_with_cidr = f"{current_ip}/{cidr}"
                            
                            # 更新進度
                            progress = 10 + int(90 * progress_count / ip_count)
                            self.update_progress_signal.emit(progress)
                            self.update_status_signal.emit(f"正在添加IP: {current_ip} ({progress_count+1}/{ip_count})...")
                            
                            # 添加IP
                            success = self.ip_manager.add_ip_address(
                                ip_with_cidr, interface
                            )
                            
                            if not success:
                                failed_ips.append((current_ip, "添加失敗"))
                                self.update_log_signal.emit(f"添加IP {current_ip} 失敗")
                            else:
                                # 記錄成功的IP
                                success_ips.append(current_ip)
                                self.update_log_signal.emit(f"成功添加IP: {ip_with_cidr}")
                        
                        except Exception as e:
                            # 記錄失敗的IP
                            failed_ips.append((current_ip, str(e)))
                            self.update_log_signal.emit(f"添加IP {current_ip} 失敗: {str(e)}")
                        
                        # 移至下一個IP
                        current_ip_obj += 1
                        progress_count += 1
                    
                    # 更新界面
                    self.update_progress_signal.emit(100)
                    
                    # 刷新IP列表
                    self.refresh_ip_list(interface)
                    
                    # 顯示結果
                    if len(failed_ips) > 0:
                        failed_msg = "\n".join([f"{ip}: {err}" for ip, err in failed_ips])
                        result_msg = (
                            f"批量添加完成。\n"
                            f"成功: {len(success_ips)} 個IP\n"
                            f"失敗: {len(failed_ips)} 個IP\n\n"
                            f"失敗詳情:\n{failed_msg}"
                        )
                        self.run_in_main_thread(
                            lambda: self.show_message_dialog("操作結果", result_msg)
                        )
                    else:
                        self.run_in_main_thread(
                            lambda: self.show_message_dialog(
                                "操作成功", f"成功添加 {len(success_ips)} 個IP地址"
                            )
                        )
                    
                    # 清空輸入框（如果全部成功）
                    if len(failed_ips) == 0:
                        self.start_ip_input.clear()
                        self.end_ip_input.clear()
                    
                except Exception as e:
                    self.update_log_signal.emit(f"批量添加IP時發生錯誤: {str(e)}")
                    self.run_in_main_thread(
                        lambda: self.show_error_dialog("錯誤", f"批量添加IP時發生錯誤: {str(e)}")
                    )
                
                finally:
                    # 恢復界面
                    self.update_status_signal.emit("批量添加IP地址完成")
                    self.update_progress_signal.emit(0)
                    
                    # 重新啟用批量添加按鈕
                    self.run_in_main_thread(lambda: self.batch_add_button.setEnabled(True))
            
            # 啟動線程
            threading.Thread(target=batch_add_thread, daemon=True).start()
    
    @pyqtSlot()
    def check_ip_config(self):
        """檢查當前IP配置"""
        if not self.ip_manager:
            return
        
        # 獲取選中的網卡
        interface = self.get_selected_interface()
        
        self.update_status_signal.emit("正在檢查IP配置...")
        self.update_progress_signal.emit(10)
        
        def check_ip_thread():
            try:
                # 獲取IP配置
                ip_config = self.ip_manager.get_ip_config(interface)
                
                # 更新日誌
                self.update_log_signal.emit(f"網卡 {interface or '(自動檢測)'} 的IP配置:")
                for line in ip_config.split('\n'):
                    if line.strip():
                        self.update_log_signal.emit(line)
                
                self.update_status_signal.emit("IP配置檢查完成")
                self.update_progress_signal.emit(100)
            except Exception as e:
                self.update_log_signal.emit(f"檢查IP配置失敗: {str(e)}")
                self.update_status_signal.emit("IP配置檢查失敗")
                self.update_progress_signal.emit(0)
                
                self.show_error_dialog("檢查IP配置錯誤", str(e))
        
        threading.Thread(target=check_ip_thread, daemon=True).start()
    
    @pyqtSlot()
    def run_ping(self):
        """執行Ping命令"""
        if not self.ip_manager:
            return
        
        # 獲取目標
        target = self.ping_target_input.text()
        if not target:
            QMessageBox.warning(self, "輸入錯誤", "請輸入Ping目標")
            return
        
        # 禁用按鈕
        self.ping_button.setEnabled(False)
        self.update_status_signal.emit(f"正在Ping {target}...")
        self.update_progress_signal.emit(10)
        
        def ping_thread():
            try:
                # 執行Ping命令
                self.update_log_signal.emit(f"正在執行: ping {target}")
                exit_code, stdout, stderr = self.ssh_client.execute_command(
                    f"ping -c 4 {target}"
                )
                
                # 更新日誌
                if exit_code == 0:
                    self.update_log_signal.emit(stdout)
                    self.update_status_signal.emit("Ping完成")
                else:
                    self.update_log_signal.emit(f"Ping失敗: {stderr}")
                    self.update_status_signal.emit("Ping失敗")
                
                self.update_progress_signal.emit(100)
            except Exception as e:
                self.update_log_signal.emit(f"執行Ping命令失敗: {str(e)}")
                self.update_status_signal.emit("Ping失敗")
                self.update_progress_signal.emit(0)
            finally:
                # 重新啟用按鈕
                self.ping_button.setEnabled(True)
        
        threading.Thread(target=ping_thread, daemon=True).start()
    
    @pyqtSlot()
    def run_traceroute(self):
        """執行Traceroute命令"""
        if not self.ip_manager:
            return
        
        # 獲取目標
        target = self.traceroute_target_input.text()
        if not target:
            QMessageBox.warning(self, "輸入錯誤", "請輸入Traceroute目標")
            return
        
        # 禁用按鈕
        self.traceroute_button.setEnabled(False)
        self.update_status_signal.emit(f"正在執行Traceroute到{target}...")
        self.update_progress_signal.emit(10)
        
        def traceroute_thread():
            try:
                # 檢查是否有traceroute命令
                _, stdout, _ = self.ssh_client.execute_command(
                    "which traceroute"
                )
                
                traceroute_cmd = stdout.strip() or "traceroute"
                
                # 執行Traceroute命令
                self.update_log_signal.emit(f"正在執行: {traceroute_cmd} {target}")
                exit_code, stdout, stderr = self.ssh_client.execute_command(
                    f"{traceroute_cmd} -m 15 {target}"
                )
                
                # 更新日誌
                if exit_code == 0 or stdout:
                    self.update_log_signal.emit(stdout)
                    self.update_status_signal.emit("Traceroute完成")
                else:
                    self.update_log_signal.emit(f"Traceroute失敗: {stderr}")
                    self.update_status_signal.emit("Traceroute失敗")
                
                self.update_progress_signal.emit(100)
            except Exception as e:
                self.update_log_signal.emit(f"執行Traceroute命令失敗: {str(e)}")
                self.update_status_signal.emit("Traceroute失敗")
                self.update_progress_signal.emit(0)
            finally:
                # 重新啟用按鈕
                self.traceroute_button.setEnabled(True)
        
        threading.Thread(target=traceroute_thread, daemon=True).start()
    
    @pyqtSlot()
    def run_dns_query(self):
        """執行DNS查詢命令"""
        if not self.ip_manager:
            return
        
        # 獲取目標
        target = self.dns_query_input.text()
        if not target:
            QMessageBox.warning(self, "輸入錯誤", "請輸入DNS查詢目標")
            return
        
        # 禁用按鈕
        self.dns_query_button.setEnabled(False)
        self.update_status_signal.emit(f"正在執行DNS查詢{target}...")
        self.update_progress_signal.emit(10)
        
        def dns_query_thread():
            try:
                # 執行DNS查詢命令
                self.update_log_signal.emit(f"正在執行DNS查詢: {target}")
                
                # 使用不同的DNS工具，優先使用dig
                _, stdout, _ = self.ssh_client.execute_command(
                    "which dig"
                )
                if stdout.strip():
                    cmd = f"dig {target} +short"
                    tool = "dig"
                else:
                    # 如果沒有dig，嘗試使用host
                    _, stdout, _ = self.ssh_client.execute_command(
                        "which host"
                    )
                    if stdout.strip():
                        cmd = f"host {target}"
                        tool = "host"
                    else:
                        # 如果都沒有，嘗試使用nslookup
                        cmd = f"nslookup {target}"
                        tool = "nslookup"
                
                self.update_log_signal.emit(f"使用 {tool} 工具查詢: {target}")
                exit_code, stdout, stderr = self.ssh_client.execute_command(cmd)
                
                # 更新日誌
                if exit_code == 0:
                    self.update_log_signal.emit(stdout)
                    self.update_status_signal.emit("DNS查詢完成")
                else:
                    self.update_log_signal.emit(f"DNS查詢失敗: {stderr}")
                    self.update_status_signal.emit("DNS查詢失敗")
                
                self.update_progress_signal.emit(100)
            except Exception as e:
                self.update_log_signal.emit(f"執行DNS查詢命令失敗: {str(e)}")
                self.update_status_signal.emit("DNS查詢失敗")
                self.update_progress_signal.emit(0)
            finally:
                # 重新啟用按鈕
                self.dns_query_button.setEnabled(True)
        
        threading.Thread(target=dns_query_thread, daemon=True).start()
    
    @pyqtSlot()
    def start_service(self):
        """啟動網絡服務"""
        self._manage_service("start")
    
    @pyqtSlot()
    def stop_service(self):
        """停止網絡服務"""
        self._manage_service("stop")
    
    @pyqtSlot()
    def restart_service(self):
        """重啟網絡服務"""
        self._manage_service("restart")
    
    @pyqtSlot()
    def check_service_status(self):
        """檢查網絡服務狀態"""
        self._manage_service("status")
    
    def _manage_service(self, action):
        """
        管理網絡服務
        
        參數:
            action (str): 服務操作 (start, stop, restart, status)
        """
        if not self.ip_manager:
            return
        
        # 獲取選擇的服務
        service_text = self.service_combo.currentText()
        
        # 根據選擇映射到實際的服務名稱
        service_map = {
            "網絡服務": "networking",
            "SSH服務": "sshd",
            "防火牆": "firewalld",
            "DHCP客戶端": "dhclient"
        }
        
        service = service_map.get(service_text, "")
        if not service:
            return
        
        # 禁用按鈕
        self.start_service_button.setEnabled(False)
        self.stop_service_button.setEnabled(False)
        self.restart_service_button.setEnabled(False)
        self.status_service_button.setEnabled(False)
        
        self.update_status_signal.emit(f"正在{action} {service_text}...")
        self.update_progress_signal.emit(10)
        
        def service_thread():
            try:
                # 檢測系統使用的服務管理工具
                _, stdout, _ = self.ssh_client.execute_command(
                    "which systemctl"
                )
                if stdout.strip():
                    # systemd
                    cmd = f"systemctl {action} {service}"
                    self.update_log_signal.emit(f"使用systemctl {action} {service}")
                    
                    if service == "dhclient" and action != "status":
                        # dhclient通常不是作為服務運行的
                        if action == "start":
                            cmd = f"dhclient -v"
                        elif action == "stop":
                            cmd = f"pkill dhclient"
                        elif action == "restart":
                            cmd = f"pkill dhclient && dhclient -v"
                    
                    # 執行服務管理命令
                    exit_code, stdout, stderr = self.ssh_client.execute_command(cmd)
                    
                    # 對於status操作，無論返回碼如何都顯示輸出
                    if action == "status" or exit_code == 0:
                        self.update_log_signal.emit(stdout)
                        self.update_status_signal.emit(f"{service_text} {action} 成功")
                    else:
                        self.update_log_signal.emit(f"{service_text} {action} 失敗: {stderr}")
                        self.update_status_signal.emit(f"{service_text} {action} 失敗")
                else:
                    # 嘗試使用service命令
                    _, stdout, _ = self.ssh_client.execute_command(
                        "which service"
                    )
                    if stdout.strip():
                        # sysvinit
                        cmd = f"service {service} {action}"
                        
                        # 執行服務管理命令
                        exit_code, stdout, stderr = self.ssh_client.execute_command(cmd)
                        
                        # 對於status操作，無論返回碼如何都顯示輸出
                        if action == "status" or exit_code == 0:
                            self.update_log_signal.emit(stdout)
                            self.update_status_signal.emit(f"{service_text} {action} 成功")
                        else:
                            self.update_log_signal.emit(f"{service_text} {action} 失敗: {stderr}")
                            self.update_status_signal.emit(f"{service_text} {action} 失敗")
                    else:
                        self.update_log_signal.emit("無法檢測服務管理工具")
                        self.update_status_signal.emit("操作失敗")
                
                self.update_progress_signal.emit(100)
            except Exception as e:
                self.update_log_signal.emit(f"執行服務管理命令失敗: {str(e)}")
                self.update_status_signal.emit("操作失敗")
                self.update_progress_signal.emit(0)
            finally:
                # 重新啟用按鈕
                self.start_service_button.setEnabled(True)
                self.stop_service_button.setEnabled(True)
                self.restart_service_button.setEnabled(True)
                self.status_service_button.setEnabled(True)
        
        threading.Thread(target=service_thread, daemon=True).start()
    
    @pyqtSlot()
    def open_firewall_port(self):
        """開放防火牆端口"""
        self._manage_firewall_port("open")
    
    @pyqtSlot()
    def close_firewall_port(self):
        """關閉防火牆端口"""
        self._manage_firewall_port("close")
    
    @pyqtSlot()
    def check_firewall_port(self):
        """檢查防火牆端口狀態"""
        self._manage_firewall_port("check")
    
    def _manage_firewall_port(self, action):
        """
        管理防火牆端口
        
        參數:
            action (str): 端口操作 (open, close, check)
        """
        if not self.ip_manager:
            return
        
        # 獲取端口和協議
        port = self.port_fw_input.text()
        protocol = self.protocol_combo.currentText().lower()
        
        # 驗證端口格式
        if not port or (not port.isdigit() and "-" not in port):
            QMessageBox.warning(self, "輸入錯誤", "請輸入有效的端口號或端口範圍 (如: 80 或 1000-2000)")
            return
        
        # 禁用按鈕
        self.open_port_button.setEnabled(False)
        self.close_port_button.setEnabled(False)
        self.check_port_button.setEnabled(False)
        
        if action == "open":
            action_text = "開放"
        elif action == "close":
            action_text = "關閉"
        else:
            action_text = "檢查"
        
        self.update_status_signal.emit(f"正在{action_text}防火牆端口 {port}/{protocol}...")
        self.update_progress_signal.emit(10)
        
        def firewall_thread():
            try:
                # 檢測系統使用的防火牆工具
                _, stdout, _ = self.ssh_client.execute_command(
                    "which firewall-cmd"
                )
                if stdout.strip():
                    # firewalld
                    firewall_tool = "firewalld"
                    
                    if action == "open":
                        cmd = f"firewall-cmd --permanent --add-port={port}/{protocol} && firewall-cmd --reload"
                    elif action == "close":
                        cmd = f"firewall-cmd --permanent --remove-port={port}/{protocol} && firewall-cmd --reload"
                    else:  # check
                        cmd = f"firewall-cmd --list-ports | grep '{port}/{protocol}'"
                else:
                    # 嘗試使用iptables
                    _, stdout, _ = self.ssh_client.execute_command(
                        "which iptables"
                    )
                    if stdout.strip():
                        # iptables
                        firewall_tool = "iptables"
                        
                        if action == "open":
                            cmd = f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT"
                        elif action == "close":
                            cmd = f"iptables -D INPUT -p {protocol} --dport {port} -j ACCEPT"
                        else:  # check
                            cmd = f"iptables -L INPUT -v -n | grep '{protocol} dpt:{port}'"
                    else:
                        # 嘗試使用ufw
                        _, stdout, _ = self.ssh_client.execute_command(
                            "which ufw"
                        )
                        if stdout.strip():
                            # ufw
                            firewall_tool = "ufw"
                            
                            if action == "open":
                                cmd = f"ufw allow {port}/{protocol}"
                            elif action == "close":
                                cmd = f"ufw delete allow {port}/{protocol}"
                            else:  # check
                                cmd = f"ufw status | grep '{port}/{protocol}'"
                        else:
                            self.update_log_signal.emit("無法檢測防火牆工具")
                            self.update_status_signal.emit("操作失敗")
                            return
                
                self.update_log_signal.emit(f"檢測到防火牆工具: {firewall_tool}")
                self.update_log_signal.emit(f"執行命令: {cmd}")
                
                # 執行防火牆命令
                exit_code, stdout, stderr = self.ssh_client.execute_command(cmd)
                
                # 更新日誌和狀態
                if action == "check":
                    if stdout.strip():
                        self.update_log_signal.emit(f"端口 {port}/{protocol} 已開放: {stdout}")
                        self.update_status_signal.emit(f"端口 {port}/{protocol} 已開放")
                    else:
                        self.update_log_signal.emit(f"端口 {port}/{protocol} 未開放")
                        self.update_status_signal.emit(f"端口 {port}/{protocol} 未開放")
                else:
                    if exit_code == 0:
                        self.update_log_signal.emit(f"成功{action_text}端口 {port}/{protocol}")
                        self.update_status_signal.emit(f"成功{action_text}端口")
                    else:
                        self.update_log_signal.emit(f"{action_text}端口失敗: {stderr}")
                        self.update_status_signal.emit(f"{action_text}端口失敗")
                
                self.update_progress_signal.emit(100)
            except Exception as e:
                self.update_log_signal.emit(f"執行防火牆命令失敗: {str(e)}")
                self.update_status_signal.emit("操作失敗")
                self.update_progress_signal.emit(0)
            finally:
                # 重新啟用按鈕
                self.open_port_button.setEnabled(True)
                self.close_port_button.setEnabled(True)
                self.check_port_button.setEnabled(True)
        
        threading.Thread(target=firewall_thread, daemon=True).start()
    
    @pyqtSlot(bool, str)
    def on_ip_added(self, success, message):
        """
        處理IP添加結果
        
        參數:
            success (bool): 是否成功
            message (str): 結果消息
        """
        if success:
            self.update_log_signal.emit(f"IP添加成功: {message}")
            self.update_status_signal.emit("IP添加成功")
            
            # 刷新所選網卡的IP列表
            interface = self.get_selected_interface()
            if interface:
                self.refresh_ip_list(interface)
        else:
            self.update_log_signal.emit(f"IP添加失敗: {message}")
            self.update_status_signal.emit("IP添加失敗")
            self.show_error_dialog("IP添加失敗", message)
    
    @pyqtSlot(bool)
    def on_ssh_connection_changed(self, is_connected):
        """
        當SSH連接狀態變更時更新UI
        
        參數:
            is_connected (bool): 是否已連接
        """
        self.is_connected = is_connected
        
        # 更新操作界面的可用狀態
        self.connect_button.setEnabled(not is_connected)
        self.disconnect_button.setEnabled(is_connected)
        self.toolbar_disconnect_action.setEnabled(is_connected)
        self.toolbar_system_info_action.setEnabled(is_connected)
        self.test_button.setEnabled(not is_connected)
        
        # 更新菜單項狀態
        self.refresh_interfaces_action.setEnabled(is_connected)
        self.check_ip_action.setEnabled(is_connected)
        
        # 更新操作界面的可用狀態
        self.refresh_interfaces_button.setEnabled(is_connected)
        self.interface_combo.setEnabled(is_connected)
        self.interface_info_button.setEnabled(is_connected)
        self.add_ip_button.setEnabled(is_connected)
        self.check_ip_button.setEnabled(is_connected)
        self.convert_to_static_button.setEnabled(is_connected)
        self.clean_netplan_button.setEnabled(is_connected)
        
        # 更新新增的IP刪除功能
        self.existing_ip_combo.setEnabled(is_connected)
        self.remove_ip_button.setEnabled(is_connected)
        
        # 更新DNS設置控件狀態
        self.use_custom_dns_checkbox.setEnabled(is_connected)
        self.primary_dns_input.setEnabled(is_connected and self.use_custom_dns_checkbox.isChecked())
        self.secondary_dns_input.setEnabled(is_connected and self.use_custom_dns_checkbox.isChecked())
        
        # 更新工具選項卡控件狀態
        self.ping_button.setEnabled(is_connected)
        self.traceroute_button.setEnabled(is_connected)
        self.dns_query_button.setEnabled(is_connected)
        self.start_service_button.setEnabled(is_connected)
        self.stop_service_button.setEnabled(is_connected)
        self.restart_service_button.setEnabled(is_connected)
        self.status_service_button.setEnabled(is_connected)
        self.open_port_button.setEnabled(is_connected)
        self.close_port_button.setEnabled(is_connected)
        self.check_port_button.setEnabled(is_connected)
        
        # 更新批量操作控件
        self.batch_add_button.setEnabled(is_connected)
        
        # 更新連接狀態顯示
        if is_connected:
            server_info = f"{self.current_server_info.get('username', '')}@{self.current_server_info.get('server', '')}:{self.current_server_info.get('port', '')}"
            self.connection_status_label.setText(f"已連接: {server_info}")
            self.statusBar.showMessage("已連接到SSH服務器")
            self.update_log_signal.emit(f"已成功連接到 {self.current_server_info.get('server', '未知主機')}")
            
            # 初始化IP管理器並獲取網卡信息
            if not self.ip_manager:
                self.ip_manager = IPManager(self.ssh_client)
            
            # 在後台刷新網卡列表
            self.refresh_interfaces()
            
        else:
            self.connection_status_label.setText("未連接")
            self.statusBar.showMessage("未連接到SSH服務器")
            self.update_log_signal.emit("已斷開SSH連接")
            
            # 禁用相關界面元素
            self.convert_to_static_button.setEnabled(False)
            self.clean_netplan_button.setEnabled(False)
            self.use_custom_dns_checkbox.setEnabled(False)
            self.primary_dns_input.setEnabled(False)
            self.secondary_dns_input.setEnabled(False)
            
            # 清空網卡和IP列表
            self.interface_combo.clear()
            self.interface_combo.addItem("自動檢測")
            self.existing_ip_combo.clear()
            self.existing_ip_combo.addItem("無IP地址")
            
            # 重置界面顯示
            self.interface_status_label.setText("未連接")
            self.interface_type_label.setText("未知")
            
            # 重置成員變量
            self.ssh_client = None
            self.ip_manager = None
            self.interfaces_list = []
            self.interface_details = {}
            self.dhcp_interfaces = set()
            self.current_server_info = {}
    
    @pyqtSlot(str)
    def update_log(self, message):
        """
        更新日誌顯示
        
        參數:
            message (str): 日誌消息
        """
        # 獲取當前時間
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 添加帶時間戳的消息
        self.log_text.append(f"[{timestamp}] {message}")
        
        # 滾動到底部
        self.log_text.moveCursor(QTextCursor.End)
    
    @pyqtSlot(str)
    def update_status(self, message):
        """
        更新狀態欄顯示
        
        參數:
            message (str): 狀態消息
        """
        self.statusBar.showMessage(message)
        
        # 確保連接狀態標籤總是顯示正確的狀態
        if self.is_connected:
            server_info = f"{self.current_server_info.get('username', '')}@{self.current_server_info.get('server', '')}:{self.current_server_info.get('port', '')}"
            self.connection_status_label.setText(f"已連接: {server_info}")
        else:
            self.connection_status_label.setText("未連接")
    
    @pyqtSlot(int)
    def update_progress(self, value):
        """
        更新進度條
        
        參數:
            value (int): 進度值 (0-100)
        """
        self.progress_bar.setValue(value)
    
    @pyqtSlot()
    def clear_log(self):
        """清除日誌顯示"""
        reply = QMessageBox.question(
            self, "確認操作", 
            "確定要清除所有日誌嗎？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.log_text.clear()
            self.update_log_signal.emit("日誌已清除")
    
    @pyqtSlot()
    def show_about_dialog(self):
        """顯示關於對話框"""
        about_dialog = AboutDialog(self)
        about_dialog.exec_()
    
    @pyqtSlot()
    def show_settings_dialog(self):
        """顯示設置對話框"""
        settings_dialog = SettingsDialog(self, self.config_manager)
        if settings_dialog.exec_() == SettingsDialog.Accepted:
            # 重新加載配置
            self._load_saved_config()
    
    @pyqtSlot()
    def show_help(self):
        """顯示幫助信息"""
        help_text = """
                    SSH IP Adder 使用指南

                    1. SSH連接
                    - 輸入服務器地址、端口、用戶名和密碼/密鑰
                    - 點擊"連接"按鈕建立連接
                    - 連接成功後可以使用各種網絡工具

                    2. IP配置
                    - 選擇網卡：從下拉列表選擇或使用自動檢測
                    - 添加IP：輸入IP地址和選擇子網掩碼，點擊"添加IP"
                    - 批量添加：設定起始IP和數量，點擊"批量添加"
                    - DHCP轉換：將DHCP配置的網卡轉換為靜態IP配置

                    3. 網絡工具
                    - Ping：測試網絡連通性
                    - Traceroute：追蹤網絡路由
                    - DNS查詢：查詢域名解析結果
                    - 服務管理：控制網絡相關服務
                    - 防火牆管理：控制端口開放狀態

                    如需更多幫助，請參閱用戶手冊或聯繫技術支援。
                    """
        
        QMessageBox.information(self, "使用說明", help_text)
    
    def show_error_dialog(self, title, message):
        """
        在主線程中顯示錯誤對話框
        
        參數:
            title (str): 對話框標題
            message (str): 錯誤消息
        """
        # 使用invokeMethod確保在主線程中執行
        QMetaObject.invokeMethod(
            self, "_show_error_dialog",
            Qt.QueuedConnection,
            Q_ARG(str, title),
            Q_ARG(str, message)
        )
    
    @pyqtSlot(str, str)
    def _show_error_dialog(self, title, message):
        """
        實際顯示錯誤對話框的方法
        
        參數:
            title (str): 對話框標題
            message (str): 錯誤消息
        """
        QMessageBox.critical(self, title, message)
    
    def show_message_dialog(self, title, message):
        """
        在主線程中顯示信息對話框
        
        參數:
            title (str): 對話框標題
            message (str): 信息消息
        """
        # 使用invokeMethod確保在主線程中執行
        QMetaObject.invokeMethod(
            self, "_show_message_dialog",
            Qt.QueuedConnection,
            Q_ARG(str, title),
            Q_ARG(str, message)
        )
    
    @pyqtSlot(str, str)
    def _show_message_dialog(self, title, message):
        """
        實際顯示信息對話框的方法
        
        參數:
            title (str): 對話框標題
            message (str): 信息消息
        """
        QMessageBox.information(self, title, message)
    
    def get_selected_interface(self):
        """
        獲取當前選中的網卡
        
        返回:
            str: 網卡名稱，如果選擇"自動檢測"則返回None
        """
        index = self.interface_combo.currentIndex()
        if index <= 0:
            # 選中了"自動檢測"
            return None
        
        # 獲取選中的網卡數據
        return self.interface_combo.itemData(index)
    
    def closeEvent(self, event: QCloseEvent):
        """
        窗口關閉事件處理
        
        參數:
            event (QCloseEvent): 關閉事件對象
        """
        # 斷開SSH連接
        if self.ssh_client and self.is_connected:
            try:
                self.update_log_signal.emit("正在斷開SSH連接...")
                self.ssh_client.disconnect()
                logger.info("程序退出時已斷開SSH連接")
            except Exception as e:
                logger.error(f"程序退出時斷開SSH連接失敗: {str(e)}")
        
        # 保存配置
        self._save_config()
        
        # 接受關閉事件
        event.accept()
    
    @pyqtSlot()
    def clean_netplan_config(self):
        """清理Netplan配置，刪除通配符配置而保留特定接口配置"""
        interface = self.get_selected_interface()
        if not interface:
            self.show_message_dialog("提示", "請先選擇網卡")
            return
            
        # 詢問使用者是否確定
        confirm = QMessageBox.question(
            self,
            "確認操作",
            f"確定要清理網卡 {interface} 的Netplan配置嗎？\n\n這將會刪除通配符配置（如eth*），並保留特定接口配置（如eth0）。\n如果特定接口配置不存在，會自動創建並繼承設置。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
            
        # 清理Netplan配置
        self.update_status_signal.emit(f"正在清理網卡 {interface} 的Netplan配置...")
        self.update_progress_signal.emit(10)
        
        # 在單獨的線程中執行清理操作
        threading.Thread(target=self.clean_netplan_thread, args=(interface,), daemon=True).start()
            
    def clean_netplan_thread(self, interface):
        """在後台線程中執行Netplan配置清理"""
        try:
            # 確保SSH連接可用
            if not self.ssh_client or not self.ssh_client.is_connected():
                self.update_log_signal.emit("SSH連接未建立，無法清理配置")
                self.update_status_signal.emit("清理配置失敗: SSH連接未建立")
                self.update_progress_signal.emit(0)
                return
                
            # 確保IP管理器已創建
            if not hasattr(self, 'ip_manager') or not self.ip_manager:
                self.ip_manager = IPManager(self.ssh_client)
                
            self.update_progress_signal.emit(30)
            
            # 執行清理操作
            result = self.ip_manager.clean_netplan_config(interface)
            
            self.update_progress_signal.emit(80)
            
            # 處理結果
            if result:
                self.update_log_signal.emit(f"成功清理網卡 {interface} 的Netplan配置")
                self.update_status_signal.emit("配置清理完成")
                
                # 刷新介面
                self.refresh_interfaces()
            else:
                self.update_log_signal.emit(f"清理網卡 {interface} 的Netplan配置失敗")
                self.update_status_signal.emit("配置清理失敗")
                
            self.update_progress_signal.emit(100)
            # 短暫停頓後重置進度條
            time.sleep(1)
            self.update_progress_signal.emit(0)
            
        except Exception as e:
            logger.error(f"清理Netplan配置時發生錯誤: {str(e)}")
            self.update_log_signal.emit(f"錯誤: {str(e)}")
            self.update_status_signal.emit("配置清理失敗")
            self.update_progress_signal.emit(0)
    
    @pyqtSlot(bool)
    def toggle_custom_dns(self, checked):
        """啟用/禁用自定義DNS輸入框"""
        self.primary_dns_input.setEnabled(checked)
        self.secondary_dns_input.setEnabled(checked)
    
    @pyqtSlot()
    def show_system_info(self):
        """顯示系統信息，包括OS類型、版本和網卡配置文件路徑"""
        if not self.is_connected or not self.ip_manager:
            return
            
        # 獲取選中的網卡
        iface = self.get_selected_interface()
        if not iface:
            self.show_error_dialog("錯誤", "請先選擇一個網卡")
            return
            
        try:
            # 獲取OS類型和版本
            os_type = self.ip_manager._os_type
            
            exit_code, os_info, _ = self.ssh_client.execute_command("cat /etc/os-release | grep -E '^(NAME|VERSION_ID)=' | tr -d '\"'")
            
            os_name = ""
            os_version = ""
            
            for line in os_info.strip().split("\n"):
                if line.startswith("NAME="):
                    os_name = line.replace("NAME=", "").strip()
                elif line.startswith("VERSION_ID="):
                    os_version = line.replace("VERSION_ID=", "").strip()
                    
            # 獲取網卡配置文件路徑
            config_file = ""
            
            if os_type == "netplan":
                config_file = self.ip_manager._find_netplan_config_file(iface)
            elif os_type == "debian":
                config_file = "/etc/network/interfaces"
            elif os_type == "redhat":
                config_file = f"/etc/sysconfig/network-scripts/ifcfg-{iface}"
                
            # 顯示系統信息
            info_text = (
                f"操作系統類型: {os_name or os_type.capitalize()}\n"
                f"操作系統版本: {os_version}\n"
                f"網卡配置文件: {config_file}\n"
                f"網卡名稱: {iface}\n"
            )
            
            QMessageBox.information(self, "系統信息", info_text)
            
        except Exception as e:
            self.show_error_dialog("獲取系統信息錯誤", str(e))