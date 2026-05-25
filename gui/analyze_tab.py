from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
                               QFileDialog, QStackedWidget, QInputDialog, QTabWidget)
from PySide6.QtCore import Qt, Signal
from gui.dashboard_tab import DashboardTab
from core.ids_core import IDSCore
import os

class AnalyzeTab(QWidget):
    import_requested = Signal(str)
    
    # Global bridge signals
    offline_flow_processed = Signal(dict)
    offline_alert_triggered = Signal(dict)
    offline_stats_updated = Signal(dict)
    
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.stack = QStackedWidget()
        
        # --- Upload View ---
        self.upload_widget = QWidget()
        upload_layout = QVBoxLayout(self.upload_widget)
        upload_layout.setAlignment(Qt.AlignCenter)
        
        lbl_title = QLabel("Offline PCAP Intelligence")
        lbl_title.setStyleSheet("font-size: 32px; font-weight: bold; color: #06B6D4; margin-bottom: 10px;")
        lbl_title.setAlignment(Qt.AlignCenter)
        
        lbl_desc = QLabel("Import an offline PCAP or PCAPNG file to run it through the Wolfsniff AI engine.\nThe traffic will be processed and visualized exactly as if it were live.")
        lbl_desc.setStyleSheet("font-size: 16px; color: #94A3B8; margin-bottom: 40px;")
        lbl_desc.setAlignment(Qt.AlignCenter)
        
        self.btn_import = QPushButton("📂 Browse PCAP File")
        self.btn_import.setFixedSize(250, 60)
        self.btn_import.setStyleSheet("""
            QPushButton { 
                background-color: #8B5CF6; color: white; font-weight: bold; 
                font-family: 'Segoe UI'; font-size: 16px; border-radius: 8px; border: none; 
            } 
            QPushButton:hover { background-color: #7C3AED; }
            QPushButton:pressed { padding-top: 5px; }
        """)
        self.btn_import.clicked.connect(self._on_initial_import)
        
        upload_layout.addWidget(lbl_title)
        upload_layout.addWidget(lbl_desc)
        upload_layout.addWidget(self.btn_import, alignment=Qt.AlignCenter)
        
        # --- Multi-Tab View ---
        self.tabs_container = QWidget()
        tabs_layout = QVBoxLayout(self.tabs_container)
        tabs_layout.setContentsMargins(0, 0, 0, 0)
        
        toolbar = QWidget()
        toolbar.setStyleSheet("background-color: #1E293B; border-bottom: 1px solid #334155;")
        tb_layout = QHBoxLayout(toolbar)
        
        self.btn_import_additional = QPushButton("📂 Import PCAP")
        self.btn_import_additional.setStyleSheet("background-color: #3B82F6; color: white; padding: 10px 20px; font-weight: bold; border-radius: 6px; border: none;")
        self.btn_import_additional.clicked.connect(self._on_import_additional)
        
        tb_layout.addWidget(self.btn_import_additional)
        tb_layout.addStretch()
        
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self._on_tab_close)
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: none; }
            QTabBar::tab { background: #1E293B; color: #94A3B8; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px; }
            QTabBar::tab:selected { background: #0F172A; color: #06B6D4; font-weight: bold; border-bottom: 2px solid #06B6D4; }
        """)
        
        tabs_layout.addWidget(toolbar)
        tabs_layout.addWidget(self.tab_widget)
        
        self.stack.addWidget(self.upload_widget)
        self.stack.addWidget(self.tabs_container)
        
        layout.addWidget(self.stack)

    def _create_pcap_tab(self, file_path, policy):
        core = IDSCore()
        dash = DashboardTab()
        dash.set_offline_mode()
        
        core.flow_processed.connect(dash.add_flow)
        dash.export_pcap_requested.connect(lambda flow_data, c=core: self._on_export_flow_pcap(flow_data, c))
        
        core.flow_processed.connect(self.offline_flow_processed.emit)
        core.alert_triggered.connect(self.offline_alert_triggered.emit)
        core.stats_updated.connect(self.offline_stats_updated.emit)
        
        tab_name = os.path.basename(file_path)
        index = self.tab_widget.addTab(dash, tab_name)
        self.tab_widget.setCurrentIndex(index)
        
        # Store core reference so it is kept alive and can be stopped
        dash.core_ref = core 
        
        try:
            core.start_capture(None, policy, offline_file=file_path)
        except Exception as e:
            QMessageBox.critical(self, "Capture Engine Error", f"Failed to start PCAP analysis.\n\nError: {str(e)}\n\nPlease ensure Npcap (or WinPcap) is installed on this system.")

    def _on_initial_import(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if file_path:
            policy, ok = QInputDialog.getItem(self, "Select Policy", "Select policy for offline PCAP analysis:", ["strict", "balanced", "conservative"], 1, False)
            if not ok:
                return
            self._create_pcap_tab(file_path, policy)
            self.stack.setCurrentIndex(1)

    def _on_import_additional(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if file_path:
            policy, ok = QInputDialog.getItem(self, "Select Policy", "Select policy for offline PCAP analysis:", ["strict", "balanced", "conservative"], 1, False)
            if not ok:
                return
            self._create_pcap_tab(file_path, policy)

    def _on_tab_close(self, index):
        dash = self.tab_widget.widget(index)
        if hasattr(dash, 'core_ref') and dash.core_ref.running:
            dash.core_ref.stop_capture()
        self.tab_widget.removeTab(index)
        dash.deleteLater()
        
        if self.tab_widget.count() == 0:
            self.stack.setCurrentIndex(0)

    def _on_export_flow_pcap(self, flow_data, core_instance):
        from PySide6.QtWidgets import QMessageBox, QFileDialog
        if not core_instance.sniffer:
            QMessageBox.warning(self, "Export Failed", "No active capture buffer to export from.")
            return
            
        src_ip = flow_data.get('src_ip')
        dst_port = flow_data.get('dst_port')
        default_name = f"Flow_{src_ip}_{dst_port}.pcap"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Flow PCAP", default_name, "PCAP Files (*.pcap)")
        
        if file_path:
            if not file_path.endswith('.pcap'): file_path += '.pcap'
            success = core_instance.sniffer.export_flow_pcap(flow_data, file_path)
            if success:
                QMessageBox.information(self, "Success", "Flow exported successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to export flow. No packets matched or write error.")
