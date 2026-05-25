import sys
import warnings
warnings.simplefilter('ignore', RuntimeWarning)
import threading
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QComboBox, QLabel, QStackedWidget, QMessageBox,
    QGraphicsOpacityEffect, QFileDialog, QButtonGroup, QProgressBar
)
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve

from gui.dashboard_tab import DashboardTab
from gui.analyze_tab import AnalyzeTab
from gui.about_tab import AboutTab
from gui.history_tab import HistoryTab
from gui.topology_tab import TopologyTab
from gui.alerts_tab import AlertsTab
from gui.stats_tab import StatsTab
from core.ids_core import IDSCore
from capture.sniffer import PacketSniffer
import time
import psutil
import logging

logger = logging.getLogger(__name__)

from PySide6.QtGui import QIcon
import os
from utils.config import RESOURCE_DIR

class MainWindow(QMainWindow):
    def __init__(self, offline_mode=False):
        super().__init__()
        self.offline_mode = offline_mode
        self.setWindowTitle("Wolfsniff")
        self.setWindowIcon(QIcon(os.path.join(RESOURCE_DIR, "icon.ico")))
        self.resize(1400, 900)
        
        # Slate Dark Mode Core Stylesheet
        self.setStyleSheet("""
            QMainWindow { background-color: #0F172A; font-family: 'Segoe UI', Arial, sans-serif; }
            QLabel { color: #F8FAFC; font-family: 'Segoe UI'; }
            
            /* ComboBox */
            QComboBox {
                background-color: #1E293B; color: #F8FAFC; padding: 8px 15px; 
                border: 1px solid #334155; border-radius: 6px; font-size: 13px; font-weight: bold;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding; subcontrol-position: top right; width: 25px;
                border-left: 1px solid #334155;
            }
            QComboBox::down-arrow {
                image: none;
                /* Drawing a custom minimal downward triangle */
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 4px solid #F8FAFC;
                width: 0; height: 0;
            }
            QComboBox:hover { border: 1px solid #06B6D4; }
            QComboBox QAbstractItemView {
                background-color: #1E293B; color: #F8FAFC; border: 1px solid #334155;
                selection-background-color: #06B6D4; selection-color: #0F172A; outline: none;
            }
            
            /* ScrollBars */
            QScrollBar:vertical { border: none; background: #0F172A; width: 10px; margin: 0px; }
            QScrollBar::handle:vertical { background: #334155; min-height: 20px; border-radius: 5px; }
            QScrollBar::handle:vertical:hover { background: #475569; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
            
            QScrollBar:horizontal { border: none; background: #0F172A; height: 10px; margin: 0px; }
            QScrollBar::handle:horizontal { background: #334155; min-width: 20px; border-radius: 5px; }
            QScrollBar::handle:horizontal:hover { background: #475569; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
        """)
        
        self.core = IDSCore()
        self.has_unsaved_packets = False
        
        self._init_ui()
        
        if self.offline_mode:
            self.sidebar.hide()
            self.toolbar_widget.hide()
            self.stack.setCurrentIndex(5)
            
        self._connect_signals()
        
    def _create_nav_btn(self, text):
        btn = QPushButton(f" {text}")
        btn.setCheckable(True)
        return btn

    def _init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # ====================
        # 1. Left Sidebar
        # ====================
        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(260)
        self.sidebar.setStyleSheet("""
            QWidget { background-color: #020617; } /* Slate 950 */
            QPushButton {
                text-align: left; padding: 12px 20px; border-radius: 0px;
                background-color: transparent; color: #94A3B8; font-size: 14px;
                font-weight: bold; border-left: 5px solid transparent;
                outline: none; border-top: none; border-right: none; border-bottom: none;
            }
            QPushButton:hover { background-color: #0F172A; color: #F8FAFC; }
            QPushButton:checked { background-color: #1E293B; color: #F8FAFC; border-left: 5px solid #06B6D4; }
        """)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 20, 0, 0)
        sidebar_layout.setSpacing(2)
        
        from PySide6.QtGui import QPixmap
        self.logo_lbl = QLabel()
        pixmap = QPixmap(os.path.join(RESOURCE_DIR, "Logo.png"))
        if not pixmap.isNull():
            # Scale gracefully keeping aspect ratio and allowing layout to manage it
            scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_lbl.setPixmap(scaled_pixmap)
            self.logo_lbl.setAlignment(Qt.AlignCenter)
            self.logo_lbl.setMinimumHeight(scaled_pixmap.height())
            sidebar_layout.addWidget(self.logo_lbl)

        title = QLabel("WOLFSNIFF")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: 900; color: #8B5CF6; padding-bottom: 25px; letter-spacing: 2px;")
        sidebar_layout.addWidget(title)
        
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        
        self.btn_nav_dash = QPushButton(" Live Dashboard")
        self.btn_nav_dash.setCheckable(True)
        self.btn_nav_dash.setChecked(True)
        
        self.btn_nav_alerts = self._create_nav_btn("Alerts")
        self.btn_nav_stats = self._create_nav_btn("Statistics")
        self.btn_nav_topo = self._create_nav_btn("Topology")
        self.btn_nav_hist = self._create_nav_btn("Database")
        self.btn_nav_analyze = self._create_nav_btn("Analyze PCAP")
        self.btn_nav_about = self._create_nav_btn("Settings")
        
        self.nav_group.addButton(self.btn_nav_dash, 0)
        self.nav_group.addButton(self.btn_nav_alerts, 1)
        self.nav_group.addButton(self.btn_nav_stats, 2)
        self.nav_group.addButton(self.btn_nav_topo, 3)
        self.nav_group.addButton(self.btn_nav_hist, 4)
        self.nav_group.addButton(self.btn_nav_analyze, 5)
        self.nav_group.addButton(self.btn_nav_about, 6)
        
        sidebar_layout.addWidget(self.btn_nav_dash)
        sidebar_layout.addWidget(self.btn_nav_alerts)
        sidebar_layout.addWidget(self.btn_nav_stats)
        sidebar_layout.addWidget(self.btn_nav_topo)
        sidebar_layout.addWidget(self.btn_nav_hist)
        sidebar_layout.addWidget(self.btn_nav_analyze)
        sidebar_layout.addWidget(self.btn_nav_about)
        sidebar_layout.addStretch()
        
        self.lbl_stats = QLabel("<b style='font-size: 15px; color: #F8FAFC;'>Wolfsniff Status</b><br><br>ML Engine: <span style='color:#10B981'>Online</span><br>Policy: <span style='color:#06B6D4'>Balanced</span><br>Mode: <span style='color:#8B5CF6'>Hybrid</span><br>Capture: <span style='color:#F59E0B'>Active IFACE</span>")
        self.lbl_stats.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: bold; padding: 10px 20px 5px 20px;")
        sidebar_layout.addWidget(self.lbl_stats)
        
        self.lbl_status = QLabel("Status: <span style='color:#E2E8F0'>STANDBY</span>")
        self.lbl_status.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: bold; padding-left: 20px; padding-bottom: 15px;")
        self.lbl_status.setTextFormat(Qt.RichText)
        sidebar_layout.addWidget(self.lbl_status)

        self.lbl_system_health = QLabel("<b style='font-size: 15px; color: #F8FAFC;'>System Health</b>")
        self.lbl_system_health.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: bold; padding-left: 20px; padding-bottom: 5px;")
        sidebar_layout.addWidget(self.lbl_system_health)
        
        # Resource Monitor
        self.lbl_cpu = QLabel("CPU: 0%")
        self.lbl_cpu.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: bold; padding-left: 20px;")
        self.bar_cpu = QProgressBar()
        self.bar_cpu.setRange(0, 100)
        self.bar_cpu.setTextVisible(False)
        self.bar_cpu.setFixedHeight(4)
        self.bar_cpu.setStyleSheet("QProgressBar { background-color: #1E293B; border: none; margin-left: 20px; margin-right: 20px; margin-bottom: 5px; } QProgressBar::chunk { background-color: #06B6D4; }")
        
        self.lbl_ram = QLabel("RAM: 0%")
        self.lbl_ram.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: bold; padding-left: 20px;")
        self.bar_ram = QProgressBar()
        self.bar_ram.setRange(0, 100)
        self.bar_ram.setTextVisible(False)
        self.bar_ram.setFixedHeight(4)
        self.bar_ram.setStyleSheet("QProgressBar { background-color: #1E293B; border: none; margin-left: 20px; margin-right: 20px; margin-bottom: 5px; } QProgressBar::chunk { background-color: #8B5CF6; }")

        sidebar_layout.addWidget(self.lbl_cpu)
        sidebar_layout.addWidget(self.bar_cpu)
        sidebar_layout.addWidget(self.lbl_ram)
        sidebar_layout.addWidget(self.bar_ram)
        
        sidebar_layout.addSpacing(40)
        
        # ====================
        # 2. Right Content Area
        # ====================
        self.right_widget = QWidget()
        self.right_widget.setStyleSheet("background-color: #0F172A;")
        right_layout = QVBoxLayout(self.right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        # Toolbar Top
        self.toolbar_widget = QWidget()
        self.toolbar_widget.setStyleSheet("background-color: #1E293B; border-bottom: 1px solid #334155;")
        toolbar_layout = QHBoxLayout(self.toolbar_widget)
        toolbar_layout.setContentsMargins(20, 15, 20, 15)
        
        btn_style = "QPushButton { background-color: %s; color: white; font-weight: bold; font-family: 'Segoe UI'; font-size: 13px; padding: 10px 20px; border-radius: 6px; border: none; } QPushButton:hover { background-color: %s; } QPushButton:pressed { padding-top: 12px; padding-bottom: 8px; } QPushButton:disabled { background-color: #334155; color: #64748B; }"
        
        self.btn_start = QPushButton("▶ Start Capture")
        self.btn_start.setStyleSheet(btn_style % ("#06B6D4", "#0891B2"))
        
        self.btn_stop = QPushButton("⏹ Stop Capture")
        self.btn_stop.setStyleSheet(btn_style % ("#F43F5E", "#E11D48"))
        self.btn_stop.setEnabled(False)
        
        self.combo_iface = QComboBox()
        self.combo_iface.addItem("Auto-Detect Interface", None)
        for iface in PacketSniffer.get_interfaces():
            self.combo_iface.addItem(iface, iface)
            
        self.btn_rules = QPushButton("📜 Load .rules")
        self.btn_rules.setStyleSheet(btn_style % ("#6366F1", "#4F46E5"))
            
                                
                                
        toolbar_layout.addWidget(self.btn_start)
        toolbar_layout.addWidget(self.btn_stop)
        
        lbl_iface = QLabel("Interface:")
        lbl_iface.setStyleSheet("font-weight: bold; margin-left: 20px; font-size: 14px; border: none;")
        toolbar_layout.addWidget(lbl_iface)
        toolbar_layout.addWidget(self.combo_iface)
        
        lbl_policy = QLabel("Policy:")
        lbl_policy.setStyleSheet("font-weight: bold; margin-left: 20px; font-size: 14px; border: none;")
        self.combo_policy = QComboBox()
        self.combo_policy.addItem("Balanced", "balanced")
        self.combo_policy.addItem("Strict", "strict")
        self.combo_policy.addItem("Conservative", "conservative")
        
        self.combo_policy.currentIndexChanged.connect(self._on_policy_changed)
        
        toolbar_layout.addWidget(lbl_policy)
        toolbar_layout.addWidget(self.combo_policy)
        
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.btn_rules)
                        
        right_layout.addWidget(self.toolbar_widget)
        
        # Stacked Widget
        self.stack = QStackedWidget()
        self.main_stack = self.stack
        
        self.dashboard_tab = DashboardTab()
        self.alerts_tab = AlertsTab()
        self.stats_tab = StatsTab()
        self.topology_tab = TopologyTab()
        self.history_tab = HistoryTab()
        self.analyze_tab = AnalyzeTab()
        self.about_tab = AboutTab()
                
        self.main_stack.addWidget(self.dashboard_tab)
        self.main_stack.addWidget(self.alerts_tab)
        self.main_stack.addWidget(self.stats_tab)
        self.main_stack.addWidget(self.topology_tab)
        self.main_stack.addWidget(self.history_tab)
        self.main_stack.addWidget(self.analyze_tab)
        self.main_stack.addWidget(self.about_tab)
        
        self.opacity_effect = QGraphicsOpacityEffect(self.stack)
        self.stack.setGraphicsEffect(self.opacity_effect)
        
        right_layout.addWidget(self.stack)
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.right_widget)

        
    def _connect_signals(self):
        self.btn_start.clicked.connect(self.on_start)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_rules.clicked.connect(self.on_load_rules)
        
        
        self.nav_group.idClicked.connect(self.on_nav_clicked)
        
        
        self.core.flow_processed.connect(self.dashboard_tab.add_flow)
        self.core.flow_processed.connect(self.topology_tab.add_flow)
        self.core.alert_triggered.connect(self.alerts_tab.add_alert)
        self.dashboard_tab.export_pcap_requested.connect(self.on_export_flow_pcap)
        
        # Bridge offline PCAP signals to global UI
        self.analyze_tab.pcap_opened.connect(self.alerts_tab.add_pcap_tab)
        self.analyze_tab.pcap_opened.connect(self.topology_tab.add_pcap_tab)
        self.analyze_tab.pcap_closed.connect(self.alerts_tab.remove_pcap_tab)
        self.analyze_tab.pcap_closed.connect(self.topology_tab.remove_pcap_tab)
        
        self.analyze_tab.offline_stats_updated.connect(self.stats_tab.update_stats)
        self.analyze_tab.offline_stats_updated.connect(self.history_tab._on_search)
        self.analyze_tab.offline_stats_updated.connect(self._update_sidebar_stats)
        
        self.core.capture_finished.connect(self.on_stop)
        
        self.core.stats_updated.connect(self._update_sidebar_stats)
        self.core.stats_updated.connect(self.stats_tab.update_stats)
        self.core.stats_updated.connect(self.history_tab._on_search)
        self.history_tab.cleared.connect(lambda: self.core.stats_updated.emit(self.core.db.get_stats()))
        

        
        # Resource Timer setup
        self.res_timer = QTimer(self)
        self.res_timer.timeout.connect(self._update_resources)
        self.res_timer.start(2000)
        
    def _update_resources(self):
        if hasattr(self, 'core') and self.core and hasattr(self.core, 'db') and self.core.db:
            stats = self.core.db.get_stats()
            self.stats_tab.update_stats(stats)

        try:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.lbl_cpu.setText(f"CPU: {cpu}%")
            self.bar_cpu.setValue(int(cpu))
            self.lbl_ram.setText(f"RAM: {ram}%")
            self.bar_ram.setValue(int(ram))
        except Exception:
            pass
        
    def _update_sidebar_stats(self, stats):
        total = stats.get('total_flows', 0)
        alerts = stats.get('total_alerts', 0)
        pass # No longer updating db stats here
        
    def on_nav_clicked(self, id):
        self.stack.setCurrentIndex(id)
        self.toolbar_widget.setVisible(id == 0)
        
        # Fade animation
        
        
        
        
        
        

        
    def on_start(self):

        if self.has_unsaved_packets:
            reply = QMessageBox(self)
            reply.setWindowTitle("Unsaved packets...")
            reply.setText("Do you want to save the captured packets before starting a new capture?\n\nYour captured packets will be lost if you don't save them.")
            
            btn_save = reply.addButton("Save", QMessageBox.AcceptRole)
            btn_continue = reply.addButton("Continue without Saving", QMessageBox.DestructiveRole)
            btn_cancel = reply.addButton("Cancel", QMessageBox.RejectRole)
            
            reply.exec()
            
            if reply.clickedButton() == btn_save:
                if not self._prompt_save_pcap():
                    return
                self._clear_capture_state()
            elif reply.clickedButton() == btn_continue:
                self._clear_capture_state()
            else:
                return


            
        try:
            self.core.flow_processed.disconnect(self.dashboard_tab.add_flow)
        except RuntimeError:
            pass
            
        self.core.flow_processed.connect(self.dashboard_tab.add_flow)
        
        iface = self.combo_iface.currentData()
        policy = self.combo_policy.currentData()
        
        try:
            self.core.start_capture(iface, policy)
            self._set_ui_running()
        except Exception as e:
            QMessageBox.critical(self, "Capture Engine Error", f"Failed to start capture.\n\nError: {str(e)}\n\nPlease ensure Npcap (or WinPcap) is installed on this system.")
        
    def on_import(self, file_path):
        # Forward the import request directly to the Analyze Tab's new multi-tab engine
        self.stack.setCurrentIndex(5)
        self.analyze_tab._create_pcap_tab(file_path, "balanced")

    def _set_ui_running(self):
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.combo_iface.setEnabled(False)
        self.lbl_status.setText('Status: <span style="color: #10B981; font-weight: bold;">RUNNING</span>')
        self.lbl_status.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: bold; padding-left: 20px; padding-bottom: 15px;")
        self.lbl_status.setTextFormat(Qt.RichText)
        
    def on_stop(self):
        self.core.stop_capture()
        self.has_unsaved_packets = True
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.combo_iface.setEnabled(True)
        self.lbl_status.setText('Status: <span style="color: #EF4444; font-weight: bold;">STOPPED</span>')
        self.lbl_status.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: bold; padding-left: 20px; padding-bottom: 15px;")
        self.lbl_status.setTextFormat(Qt.RichText)
        
    def on_export_flow_pcap(self, flow_data):
        if not self.core.sniffer:
            QMessageBox.warning(self, "Export Failed", "No active capture buffer to export from.")
            return
            
        src_ip = flow_data.get('src_ip')
        dst_port = flow_data.get('dst_port')
        default_name = f"Flow_{src_ip}_{dst_port}.pcap"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Flow PCAP", default_name, "PCAP Files (*.pcap)")
        
        if file_path:
            if not file_path.endswith('.pcap'): file_path += '.pcap'
            success = self.core.sniffer.export_flow_pcap(flow_data, file_path)
            if success:
                QMessageBox.information(self, "Success", "Flow exported successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to export flow. No packets matched or write error.")
                
    def on_load_rules(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Suricata/Snort Rules", "", "Rule Files (*.rules);;All Files (*)")
        if file_path:
            count = self.core.load_rules(file_path)
            if count >= 0:
                QMessageBox.information(self, "Rules Loaded", f"Successfully loaded {count} signature rules.")
            else:
                QMessageBox.critical(self, "Error", "Failed to parse the rules file.")
            
    def closeEvent(self, event):
        self.on_stop()
        event.accept()




    def _on_policy_changed(self):
        policy = self.combo_policy.currentData()
        if hasattr(self, 'core') and hasattr(self.core, 'set_policy'):
            self.core.set_policy(policy)
        logger.info(f"UI Switched Active Policy to: {policy.upper()}")
        
        # Update sidebar
        if hasattr(self, 'lbl_stats'):
            lbl_text = self.lbl_stats.text()
            import re
            new_text = re.sub(r'Policy: <span[^>]+>[a-zA-Z]+</span>', f"Policy: <span style='color:#06B6D4'>{policy.capitalize()}</span>", lbl_text)
            self.lbl_stats.setText(new_text)

    def _prompt_save_pcap(self):
        default_name = f"Wolfsniff_{time.strftime('%H-%M-%S_%Y.%m.%d')}.pcap"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", default_name, "PCAP Files (*.pcap)")
        if file_path:
            if not file_path.endswith('.pcap'): file_path += '.pcap'
            success = self.core.save_pcap(file_path)
            if success:
                self.has_unsaved_packets = False
                QMessageBox.information(self, "Success", "PCAP saved successfully.")
                return True
            else:
                QMessageBox.critical(self, "Error", "Failed to save PCAP.")
                return False
        return False

    def _clear_capture_state(self):
        self.setWindowTitle("Wolfsniff")
        self.dashboard_tab.clear_data()
        self.dashboard_tab.commit_clear()
        self.core.clear_stats()
        self.has_unsaved_packets = False
