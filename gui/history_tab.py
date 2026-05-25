from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout, QPushButton, QLineEdit, QLabel
from PySide6.QtCore import Qt
import sqlite3
from utils.config import DB_PATH

class HistoryTab(QWidget):
    from PySide6.QtCore import Signal
    cleared = Signal()
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Top controls
        ctrl_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search IPs, Protocols, or Severity...")
        self.search_box.setStyleSheet("padding: 10px; font-size: 14px; border-radius: 6px; background-color: #1E293B; color: white; border: 1px solid #334155;")
        
        self.btn_search = QPushButton("Search Database")
        self.btn_search.setStyleSheet("QPushButton { background-color: #3B82F6; color: white; padding: 10px; border-radius: 6px; font-weight: bold; border: none; } QPushButton:hover { background-color: #2563EB; }")
        self.btn_search.clicked.connect(self._on_search)
        
        self.lbl_total = QLabel("Total Records: 0")
        self.lbl_total.setStyleSheet("color: #94A3B8; font-weight: bold; padding: 0 10px;")
        
        self.btn_delete = QPushButton("Delete All")
        self.btn_delete.setStyleSheet("QPushButton { background-color: #EF4444; color: white; padding: 10px; border-radius: 6px; font-weight: bold; border: none; } QPushButton:hover { background-color: #DC2626; }")
        self.btn_delete.clicked.connect(self._on_delete_all)
        
        self.btn_export = QPushButton("Export PCAP")
        self.btn_export.setStyleSheet("QPushButton { background-color: #10B981; color: white; padding: 10px; border-radius: 6px; font-weight: bold; border: none; } QPushButton:hover { background-color: #059669; }")
        self.btn_export.clicked.connect(self._on_export_pcap)
        
        ctrl_layout.addWidget(self.search_box)
        ctrl_layout.addWidget(self.btn_search)
        ctrl_layout.addWidget(self.lbl_total)
        ctrl_layout.addWidget(self.btn_delete)
        ctrl_layout.addWidget(self.btn_export)
        
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["ID", "Timestamp", "Src IP", "Dst IP", "Port", "Proto", "Score", "Severity", "Explanation"])
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
        
        layout.addLayout(ctrl_layout)
        layout.addWidget(self.table)
        
        self._on_search()
        
    def _on_search(self, *args):
        query = self.search_box.text().strip().lower()
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if query:
                cursor.execute('''
                    SELECT f.id, f.timestamp, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.threat_score, f.severity, COALESCE(a.explanation, 'Normal Traffic')
                    FROM flows f
                    LEFT JOIN alerts a ON f.id = a.flow_id
                    WHERE f.src_ip LIKE ? OR f.dst_ip LIKE ? OR f.protocol LIKE ? OR f.severity LIKE ?
                    ORDER BY f.timestamp DESC LIMIT 1000
                ''', (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
            else:
                cursor.execute('''
                    SELECT f.id, f.timestamp, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.threat_score, f.severity, COALESCE(a.explanation, 'Normal Traffic')
                    FROM flows f
                    LEFT JOIN alerts a ON f.id = a.flow_id
                    ORDER BY f.timestamp DESC LIMIT 1000
                ''')
                
            rows = cursor.fetchall()
            
            # Get total count
            cursor.execute('SELECT COUNT(*) FROM flows')
            total_flows = cursor.fetchone()[0]
            self.lbl_total.setText(f"Total Logged Flows: {total_flows}")
            
            conn.close()
            
            self.table.setRowCount(0)
            for row_idx, row_data in enumerate(rows):
                self.table.insertRow(row_idx)
                for col_idx, value in enumerate(row_data):
                    val_str = str(value)
                    if col_idx == 6:
                        val_str = f"{float(value)*100:.1f}%"
                    item = QTableWidgetItem(val_str)
                    item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                    item.setTextAlignment(Qt.AlignCenter if col_idx in [0, 4, 5, 6, 7] else Qt.AlignLeft | Qt.AlignVCenter)
                    self.table.setItem(row_idx, col_idx, item)
                    
                    if col_idx == 7: # Severity
                        if value == 'HIGH': item.setForeground(Qt.red)
                        elif value == 'MEDIUM': item.setForeground(Qt.yellow)
                        else: item.setForeground(Qt.green)
                        
        except Exception as e:
            print(f"DB Error: {e}")

    def _on_export_pcap(self):
        from PySide6.QtWidgets import QFileDialog, QMessageBox
        from datetime import datetime
        import sqlite3
        from utils.config import DB_PATH
        from scapy.all import Ether, IP, TCP, UDP
        from scapy.utils import wrpcap
        import time
        
        default_name = f"Wolfsniff_{datetime.now().strftime('%H-%M-%S_%Y.%m.%d')}_database.pcap"
        path, _ = QFileDialog.getSaveFileName(self, "Export Database", default_name, "PCAP Files (*.pcap)")
        if not path:
            return
            
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT f.timestamp, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol
                FROM flows f
                ORDER BY f.timestamp ASC
            ''')
            rows = cursor.fetchall()
            conn.close()
            
            pkts = []
            last_t = 0.0
            for row_idx, r in enumerate(rows):
                ts_str, src_ip, dst_ip, src_port, dst_port, protocol = r
                
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
            QMessageBox.information(self, "Export Successful", f"Database exported successfully as PCAP to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export PCAP: {str(e)}")

    def _on_delete_all(self):
        from PySide6.QtWidgets import QMessageBox
        reply = QMessageBox.warning(
            self, "Delete All Records", 
            "Are you sure you want to permanently delete all records from the database?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM alerts")
                cursor.execute("DELETE FROM flows")
                conn.commit()
                conn.close()
                self._on_search()
                QMessageBox.information(self, "Deleted", "All database records have been deleted.")
            except Exception as e:
                print(f"Delete Error: {e}")
