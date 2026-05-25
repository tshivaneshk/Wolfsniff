from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QHBoxLayout, QPushButton
from PySide6.QtGui import QColor, QFont
from PySide6.QtCore import Qt

class AlertsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        top_layout = QHBoxLayout()
        title = QLabel("Real-Time Threat Alerts (MITRE ATT&CK Linked)")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #d83b01;")
        top_layout.addStretch()
        top_layout.addWidget(title)
        top_layout.addStretch()
        
        self.btn_export = QPushButton("Export PCAP")
        self.btn_export.setStyleSheet("QPushButton { background-color: #10B981; color: white; font-weight: bold; font-family: 'Segoe UI'; font-size: 13px; padding: 10px 20px; border-radius: 6px; border: none; } QPushButton:hover { background-color: #059669; }")
        top_layout.addWidget(self.btn_export)
        
        self.lbl_no_threats = QLabel("Status: Clean / No Threats Detected")
        self.lbl_no_threats.setStyleSheet("font-size: 24px; font-weight: bold; color: #10B981; padding: 50px;")
        self.lbl_no_threats.setAlignment(Qt.AlignCenter)
        
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Score", "Source IP", "Src Port", "Target IP", "Dst Port", "Protocol", "Explanation"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(True)
        self.table.verticalHeader().setStyleSheet("QHeaderView::section { background-color: #1E293B; color: #cbd5e1; border: none; }")
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setStyleSheet("""
            QTableWidget { background-color: #0F172A; color: #cbd5e1; border: none; font-size: 13px; }
            QHeaderView::section { background-color: #1E293B; color: #94A3B8; font-weight: bold; border: none; padding: 8px; text-align: left; }
            QTableWidget::item { padding: 5px; border-bottom: 1px solid #1E293B; }
            QTableWidget::item:selected { background-color: #1E293B; color: #3B82F6; }
        """)
        
        self.layout.addLayout(top_layout)
        self.layout.addWidget(self.lbl_no_threats)
        self.layout.addWidget(self.table)
        
        self.table.hide()
        self.btn_export.hide()
        self.btn_export.clicked.connect(self.export_pcap)
        self.table.itemClicked.connect(self.show_deep_report)
        
    def add_alert(self, alert_data):
        self.lbl_no_threats.hide()
        self.table.show()
        self.btn_export.show()
        
        row = 0
        self.table.insertRow(row)
        
        t = alert_data.get('timestamp', '')
        severity = alert_data.get('severity', 'LOW')
        score = f"{alert_data.get('threat_score', 0)*100:.1f}%"
        
        cols = [
            t, severity, score,
            str(alert_data.get('src_ip')), str(alert_data.get('src_port')),
            str(alert_data.get('dst_ip')), str(alert_data.get('dst_port')),
            str(alert_data.get('protocol')), alert_data.get('explanation', '')
        ]
        
        for col_idx, val in enumerate(cols):
            item = QTableWidgetItem(val)
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            item.setData(Qt.UserRole, alert_data)
            self.table.setItem(row, col_idx, item)
            
            if severity == 'HIGH':
                item.setBackground(QColor('#450a0a'))
                item.setForeground(QColor('#fca5a5'))
                item.setFont(QFont("Consolas", 10, QFont.Bold))
            elif severity == 'MEDIUM':
                item.setBackground(QColor('#422006'))
                item.setForeground(QColor('#fcd34d'))
                item.setFont(QFont("Consolas", 10, QFont.Bold))
            elif severity == 'CRITICAL':
                item.setBackground(QColor('#7f1d1d'))
                item.setForeground(QColor('#fef2f2'))
                item.setFont(QFont("Consolas", 10, QFont.Bold))

        if self.table.rowCount() > 200:
            self.table.removeRow(self.table.rowCount() - 1)

    def export_pcap(self):
        from PySide6.QtWidgets import QFileDialog, QMessageBox
        from datetime import datetime
        from scapy.all import Ether, IP, TCP, UDP
        from scapy.utils import wrpcap
        import time
        
        default_name = f"Wolfsniff_{datetime.now().strftime('%H-%M-%S_%Y.%m.%d')}_alerts.pcap"
        path, _ = QFileDialog.getSaveFileName(self, "Export Alerts", default_name, "PCAP Files (*.pcap)")
        if not path:
            return
            
        try:
            pkts = []
            last_t = 0.0
            for r in range(self.table.rowCount() - 1, -1, -1):
                item = self.table.item(r, 0)
                data = item.data(Qt.UserRole)
                if data:
                    ts_str = str(data.get('timestamp', ''))
                    try:
                        t = float(ts_str)
                    except ValueError:
                        try:
                            # Convert '2026-05-24 23:05:48' to float timestamp
                            t = time.mktime(time.strptime(ts_str, '%Y-%m-%d %H:%M:%S'))
                        except:
                            t = time.time()
                    
                    if t <= last_t:
                        t = last_t + 0.000010
                    last_t = t
                    
                    src_ip = data.get('src_ip', '0.0.0.0')
                    dst_ip = data.get('dst_ip', '0.0.0.0')
                    src_port = data.get('src_port', 0)
                    dst_port = data.get('dst_port', 0)
                    protocol = data.get('protocol', '')
                    
                    pkt = Ether() / IP(src=src_ip, dst=dst_ip)
                    sport = int(src_port) if src_port else 0
                    dport = int(dst_port) if dst_port else 0
                    
                    if str(protocol).upper() == 'TCP':
                        pkt = pkt / TCP(sport=sport, dport=dport)
                    elif str(protocol).upper() == 'UDP':
                        pkt = pkt / UDP(sport=sport, dport=dport)
                        
                    pkt.time = t
                    pkts.append(pkt)
            
            wrpcap(path, pkts)
            QMessageBox.information(self, "Export Successful", f"Alerts exported successfully to PCAP at {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export PCAP: {str(e)}")

    def show_deep_report(self, item):
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton
        import ast
        alert_data = item.data(Qt.UserRole)
        if not alert_data: return
        
        try:
            import sqlite3
            from utils.config import DB_PATH
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT threat_intel FROM alerts 
                WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ? AND protocol = ?
                ORDER BY timestamp DESC LIMIT 1
            ''', (alert_data.get('src_ip'), alert_data.get('dst_ip'), alert_data.get('src_port'), alert_data.get('dst_port'), alert_data.get('protocol')))
            row = cursor.fetchone()
            if row and row[0]:
                alert_data['threat_intel'] = row[0]
            conn.close()
        except Exception as e:
            pass
            
        
        dlg = QDialog(self)
        dlg.setWindowTitle("Deep Packet Analysis Report")
        dlg.resize(700, 500)
        
        layout = QVBoxLayout(dlg)
        text = QTextBrowser()
        text.setReadOnly(True)
        text.setStyleSheet("background-color: #0F172A; color: #F8FAFC; font-family: Consolas; font-size: 14px; border: 1px solid #334155; padding: 15px;")
        
        report = f"===========================================================\n"
        report += f"                 DEEP PACKET ANALYSIS REPORT                 \n"
        report += f"===========================================================\n\n"
        
        report += f"[+] BASIC FLOW INFORMATION\n"
        report += f"    Timestamp:    {alert_data.get('timestamp', 'N/A')}\n"
        report += f"    Protocol:     {alert_data.get('protocol', 'N/A')}\n\n"
        
        report += f"[+] NETWORK ENDPOINTS\n"
        report += f"    Source:       {alert_data.get('src_ip')}:{alert_data.get('src_port')}\n"
        report += f"    Destination:  {alert_data.get('dst_ip')}:{alert_data.get('dst_port')}\n\n"
        
        report += f"[+] MACHINE LEARNING DIAGNOSTICS\n"
        report += f"    Severity:     {alert_data.get('severity', 'UNKNOWN')}\n"
        report += f"    Threat Score: {alert_data.get('threat_score', 0)*100:.2f}%\n"
        report += f"    Explanation:  {alert_data.get('explanation', 'N/A')}\n\n"
        
        intel_raw = alert_data.get('threat_intel')
        if intel_raw and intel_raw != "None":
            try:
                intel = ast.literal_eval(intel_raw)
                report += f"[+] ABUSEIPDB API RESULTS (EXTERNAL THREAT INTELLIGENCE)\n"
                
                if intel.get('reports', 0) == 0:
                    report += f"    No data found in db\n"
                else:
                    report += f"    Domain:       {intel.get('domain', 'Unknown')}\n"
                    report += f"    Reputation:   {intel.get('score', 0)} / 100\n"
                    report += f"    Reports:      {intel.get('reports', 0)}\n"
                    if 'isp' in intel:
                        report += f"    ISP:          {intel.get('isp', 'Unknown')}\n"
                        report += f"    Usage Type:   {intel.get('usageType', 'Unknown')}\n"
                        report += f"    Location:     {intel.get('city', 'Unknown')}, {intel.get('country', 'Unknown')}\n"
                    report += f"\n    <a href='https://www.abuseipdb.com/check/{alert_data.get('dst_ip')}' style='color: #06B6D4; text-decoration: none;'>[View Full Report on AbuseIPDB]</a>\n"
            except:
                report += f"[+] ABUSEIPDB API RESULTS (EXTERNAL THREAT INTELLIGENCE)\n    {intel_raw}\n"
                report += f"\n    <a href='https://www.abuseipdb.com/check/{alert_data.get('dst_ip')}' style='color: #06B6D4; text-decoration: none;'>[View Full Report on AbuseIPDB]</a>\n"
                
        text.setOpenExternalLinks(True)
        text.setHtml(f"<pre style='font-family: Consolas; color: #F8FAFC; margin: 0;'>{report}</pre>")
        
        btn_close = QPushButton("Close Analysis")
        btn_close.clicked.connect(dlg.accept)
        btn_close.setStyleSheet("QPushButton { background-color: #334155; color: white; padding: 10px; border-radius: 6px; font-weight: bold; } QPushButton:hover { background-color: #475569; }")
        
        layout.addWidget(text)
        layout.addWidget(btn_close)
        
        dlg.exec()
