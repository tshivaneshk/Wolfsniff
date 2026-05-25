import time
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QSplitter, QTextEdit, QPushButton

from PySide6.QtCore import Qt, Signal, Slot, QTimer
from PySide6.QtGui import QColor, QFont, QBrush
import pyqtgraph as pg
import numpy as np
from utils.dns_resolver import DNSResolver

class DashboardTab(QWidget):
    dns_resolved = Signal(str, str)
    export_pcap_requested = Signal(dict)

    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        self.dns_resolver = DNSResolver()
        self.flow_rows = {}
        
        self.dns_resolved.connect(self._update_table_domains)
        
        # Top Charts Layout
        charts_layout = QHBoxLayout()
        
        # Threat Score Line Plot (Dark Mode)
        self.plot_widget = pg.PlotWidget(title="Traffic Volume & Alerts (Packets/sec)")
        self.plot_widget.setBackground('#1E293B')
        self.plot_widget.getAxis('left').setPen('#94A3B8')
        self.plot_widget.getAxis('bottom').setPen('#94A3B8')
        self.plot_widget.setLabel('left', 'Packets/sec', color='#94A3B8')
        self.plot_widget.setLabel('bottom', 'Time (s)', color='#94A3B8')
        self.plot_widget.setMouseEnabled(x=False, y=False)
        self.plot_widget.showGrid(x=True, y=True, alpha=0.2)
        self.plot_widget.addLegend(offset=(10, 10))
        
        self.plot_curve_vol = self.plot_widget.plot(pen=pg.mkPen(color='#3B82F6', width=2), name="Total Traffic")
        self.plot_curve_alert = self.plot_widget.plot(pen=pg.mkPen(color='#F43F5E', width=2), name="Alerts")
        
        self.time_data = []
        self.vol_data = []
        self.alert_data = []
        
        self.current_vol_count = 0
        self.current_alert_count = 0
        self.start_time = time.time()
        
        self.graph_timer = QTimer(self)
        self.graph_timer.timeout.connect(self._update_graph)
        self.graph_timer.start(1000)
        
        self.flow_buffer = [] # Buffer for restoring data
        
        # Protocol Breakdown Bar Chart
        self.proto_widget = pg.PlotWidget(title="Protocol Breakdown")
        self.proto_widget.setBackground('#1E293B')
        self.proto_widget.getAxis('left').setPen('#94A3B8')
        self.proto_widget.getAxis('bottom').setPen('#94A3B8')
        self.proto_widget.setLabel('left', 'Total Packets', color='#94A3B8')
        self.proto_widget.getAxis('bottom').setTicks([[(0, 'TCP'), (1, 'UDP'), (2, 'ICMP'), (3, 'OTHER')]])
        self.proto_widget.setMouseEnabled(x=False, y=False)
        
        self.proto_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        self.proto_bg = pg.BarGraphItem(x=[0, 1, 2, 3], height=[0, 0, 0, 0], width=0.6, brushes=['#3B82F6', '#10B981', '#F59E0B', '#64748B'])
        self.proto_widget.addItem(self.proto_bg)
        
        # Traffic Filter Bar
        filter_layout = QHBoxLayout()
        lbl_filter = QLabel("Traffic Filter:")
        lbl_filter.setStyleSheet("font-weight: bold; color: #94A3B8; margin-left: 5px; font-size: 14px;")
        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter by IP, Protocol, Geo-Location, or Severity (e.g., HIGH, 192.168, TCP, Russia)")
        self.filter_box.setStyleSheet("background-color: #1E293B; color: #F8FAFC; padding: 10px; border: 1px solid #334155; border-radius: 6px; font-size: 13px;")
        self.filter_box.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(lbl_filter)
        filter_layout.addWidget(self.filter_box)
        
        # Table
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Geo/ISP', 'Protocol', 'Length', 'Info', 'Threat %', 'Severity'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch) # Info stretches
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        
        # Premium Dark Mode Table Styling
        self.table.setStyleSheet("""
            QTableWidget { background-color: #0F172A; color: #F8FAFC; border: 1px solid #334155; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 13px; outline: none; gridline-color: #1E293B; }
            QHeaderView::section { background-color: #1E293B; color: #94A3B8; padding: 8px; border: 1px solid #334155; border-top: none; border-left: none; font-weight: bold; }
        """)
        self.table.setShowGrid(True)
        
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        
        charts_widget = QWidget()
        charts_widget_layout = QHBoxLayout(charts_widget)
        charts_widget_layout.setContentsMargins(0, 0, 0, 0)
        charts_widget_layout.addWidget(self.plot_widget, stretch=3)
        charts_widget_layout.addWidget(self.proto_widget, stretch=1)
        
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.addLayout(filter_layout)
        table_layout.addWidget(self.table)
        
        self.top_splitter = QSplitter(Qt.Vertical)
        self.top_splitter.addWidget(charts_widget)
        self.top_splitter.addWidget(table_widget)
        self.top_splitter.setSizes([300, 600])
        
        # Bottom Detail Pane
        self.detail_container = QWidget()
        self.detail_container.setStyleSheet("background-color: #1E293B; border: 1px solid #334155; border-radius: 6px;")
        detail_layout = QVBoxLayout(self.detail_container)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(0)
        
        top_detail_bar = QHBoxLayout()
        top_detail_bar.setContentsMargins(15, 10, 15, 0)
        lbl_detail_title = QLabel("Wolfsniff Analyst")
        lbl_detail_title.setStyleSheet("color: #94A3B8; font-weight: bold; font-size: 14px; border: none;")
        
        self.btn_close_detail = QPushButton("✖")
        self.btn_close_detail.setFixedSize(24, 24)
        self.btn_close_detail.setStyleSheet("""
            QPushButton { background-color: transparent; color: #64748B; border: none; font-weight: bold; }
            QPushButton:hover { color: #F43F5E; }
        """)
        self.btn_close_detail.clicked.connect(self.detail_container.hide)
        
        top_detail_bar.addWidget(lbl_detail_title)
        top_detail_bar.addStretch()
        top_detail_bar.addWidget(self.btn_close_detail)
        
        self.detail_pane = QTextEdit()
        self.detail_pane.setReadOnly(True)
        self.detail_pane.setStyleSheet("background-color: transparent; color: #F8FAFC; font-family: 'Segoe UI'; font-size: 14px; border: none; padding: 15px;")
        
        detail_layout.addLayout(top_detail_bar)
        detail_layout.addWidget(self.detail_pane)
        self.detail_container.hide() # Hidden by default
        
        # Splitter
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.top_splitter)
        self.splitter.addWidget(self.detail_container)
        self.splitter.setSizes([700, 250])
        
        self.layout.addWidget(self.splitter)
        
        self.packet_counter = 0

    def set_offline_mode(self):
        self.graph_timer.stop()
        self.top_splitter.widget(0).hide()

    def _update_graph(self):
        current_time = time.time() - self.start_time
        self.time_data.append(current_time)
        self.vol_data.append(self.current_vol_count)
        self.alert_data.append(self.current_alert_count)
        
        if len(self.time_data) > 60:
            self.time_data.pop(0)
            self.vol_data.pop(0)
            self.alert_data.pop(0)
            
        self.plot_curve_vol.setData(self.time_data, self.vol_data)
        self.plot_curve_alert.setData(self.time_data, self.alert_data)
        
        if self.time_data:
            self.plot_widget.setXRange(self.time_data[0], max(self.time_data[0] + 60, self.time_data[-1] + 1), padding=0)
        
        self.current_vol_count = 0
        self.current_alert_count = 0
        
    def clear_data(self):
        self._backup_buffer = list(self.flow_buffer)
        self.flow_buffer.clear()
        self.table.setRowCount(0)
        self.table.setAlternatingRowColors(False)
        self.flow_rows.clear()
        self.packet_counter = 0
        self.proto_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        self.proto_bg.setOpts(height=[0, 0, 0, 0])
        self.vol_data = []
        self.alert_data = []
        self.time_data = []
        self.plot_curve_vol.setData([], [])
        self.plot_curve_alert.setData([], [])
        self.detail_container.hide()
        
    def restore_data(self):
        if hasattr(self, '_backup_buffer'):
            for fd in self._backup_buffer:
                self.add_flow(fd)
            self._backup_buffer.clear()
            
    def commit_clear(self):
        if hasattr(self, '_backup_buffer'):
            self._backup_buffer.clear()

    def _apply_filter(self, text):
        query = text.lower()
        for r in range(self.table.rowCount()):
            match = False
            for c in range(self.table.columnCount()):
                item = self.table.item(r, c)
                if item and query in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(r, not match)

    def _on_dns_resolved(self, ip, domain):
        self.dns_resolved.emit(ip, domain)
        
    @Slot(str, str)
    def _update_table_domains(self, ip, domain):
        for r in range(self.table.rowCount()):
            info_item = self.table.item(r, 7)
            if info_item:
                data = info_item.data(Qt.UserRole)
                if data and isinstance(data, dict):
                    if data.get('src_ip') == ip or data.get('dst_ip') == ip:
                        s_dom = self.dns_resolver.cache.get(data['src_ip'], data['src_ip'])
                        d_dom = self.dns_resolver.cache.get(data['dst_ip'], data['dst_ip'])
                        new_info = f"{s_dom}:{data['src_port']} -> {d_dom}:{data['dst_port']} [{data['explanation']}]"
                        info_item.setText(new_info)
                        
    def _on_row_selected(self):
        selected = self.table.selectedItems()
        if not selected: return
        row = selected[0].row()
        info_item = self.table.item(row, 7)
        if not info_item: return
        
        data = info_item.data(Qt.UserRole)
        if not data or not isinstance(data, dict): return
        
        reasons = data.get('reasons', [])
        activities = data.get('activities', [])
        actions = data.get('recommendations', [])
        geo_str = f"{data.get('geo_country', 'Unknown')} ({data.get('geo_isp', 'Unknown')})"
        
        if not reasons:
            reasons_html = "<p style='color: #10B981;'>Baseline Traffic Metrics.</p>"
            activities_html = "<p style='color: #94A3B8;'>-</p>"
            actions_html = "<p style='color: #94A3B8;'>-</p>"
        else:
            reasons_html = "<ul style='margin-top: 5px;'>" + "".join([f"<li>{r}</li>" for r in reasons]) + "</ul>"
            activities_html = "<ul style='margin-top: 5px;'>" + "".join([f"<li>{a}</li>" for a in activities]) + "</ul>"
            actions_html = "<ul style='margin-top: 5px;'>" + "".join([f"<li>{a}</li>" for a in actions]) + "</ul>"
        
        html = f"""
        <h2 style="color: #06B6D4; margin-bottom: 5px; margin-top: 0px;">Inspection Report</h2>
        <div style="color: #94A3B8; font-size: 13px; margin-bottom: 15px;"><b>Date:</b> {time.strftime('%x', time.localtime(data.get('timestamp', time.time())))} and <b>Time:</b> {time.strftime('%X', time.localtime(data.get('timestamp', time.time())))} | <b>Connection:</b> {data.get('src_ip')}:{data.get('src_port')} &rarr; {data.get('dst_ip')}:{data.get('dst_port')} | <b>Geo:</b> {geo_str}</div>
        
        <table width="100%" cellpadding="5">
        <tr>
            <td width="33%" valign="top">
                <h3 style="color: #F43F5E; margin-bottom: 0px;">Flagged Behavior</h3>
                {reasons_html}
            </td>
            <td width="33%" valign="top">
                <h3 style="color: #F59E0B; margin-bottom: 0px;">Predicted Activity</h3>
                {activities_html}
            </td>
            <td width="33%" valign="top">
                <h3 style="color: #10B981; margin-bottom: 0px;">Recommended Action</h3>
                {actions_html}
            </td>
        </tr>
        </table>
        """
        self.detail_pane.setHtml(html)
        self.detail_container.show()
        
    def _show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item: return
        
        row = item.row()
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #1E293B; color: white; border: 1px solid #334155; } QMenu::item:selected { background-color: #3B82F6; }")
        
        export_action = menu.addAction("💾 Export PCAP for this Flow")
        
        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == export_action:
            info_item = self.table.item(row, 7)
            if info_item:
                data = info_item.data(Qt.UserRole)
                if data:
                    self.export_pcap_requested.emit(data)
        
    def add_flow(self, flow_data):
        flow_id = f"{flow_data.get('src_ip')}_{flow_data.get('dst_ip')}_{flow_data.get('src_port')}_{flow_data.get('dst_port')}_{flow_data.get('protocol')}"
        src_ip = flow_data.get('src_ip')
        dst_ip = flow_data.get('dst_ip')
        
        src_domain = self.dns_resolver.resolve(src_ip, self._on_dns_resolved)
        dst_domain = self.dns_resolver.resolve(dst_ip, self._on_dns_resolved)
        
        proto = str(flow_data.get('proto', '')).upper()
        length = str(flow_data.get('sbytes', 0) + flow_data.get('dbytes', 0))
        geo_str = f"{flow_data.get('geo_country', 'Unknown')}"
        
        info_dict = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': flow_data.get('src_port'),
            'dst_port': flow_data.get('dst_port'),
            'explanation': flow_data.get('explanation', ''),
            'reasons': flow_data.get('reasons', []),
            'activities': flow_data.get('activities', []),
            'recommendations': flow_data.get('recommendations', []),
            'geo_country': flow_data.get('geo_country', ''),
            'geo_isp': flow_data.get('geo_isp', ''),
            'timestamp': flow_data.get('timestamp', time.time())
        }
        
        info_str = f"{src_domain}:{info_dict['src_port']} -> {dst_domain}:{info_dict['dst_port']} [{info_dict['explanation']}]"
        
        threat_score = flow_data.get('threat_score', 0) * 100
        severity = flow_data.get('severity', 'LOW')
        
        self.flow_buffer.append(flow_data)
        if len(self.flow_buffer) > 1000:
            self.flow_buffer.pop(0)
            
        self.current_vol_count += 1
        if threat_score > 50:
            self.current_alert_count += 1
            
        row = -1
        if flow_id in self.flow_rows:
            row = self.flow_rows[flow_id].row()
            
        if row != -1:
            self.table.item(row, 6).setText(length)
            info_item = self.table.item(row, 7)
            info_item.setText(info_str)
            info_item.setData(Qt.UserRole, info_dict)
            self.table.item(row, 8).setText(f"{threat_score:.1f}%")
            self.table.item(row, 9).setText(severity)
            self._color_row(row, proto, severity)
        else:
            self.packet_counter += 1
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            if 'timestamp' in flow_data:
                t = time.strftime('%H:%M:%S', time.localtime(flow_data['timestamp']))
            else:
                t = time.strftime('%H:%M:%S', time.localtime())
            
            def create_item(txt, user_data=None):
                item = QTableWidgetItem(txt)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled) # Prevent user editing
                if user_data: item.setData(Qt.UserRole, user_data)
                return item
                
            item_no = create_item(str(self.packet_counter), flow_id)
            self.flow_rows[flow_id] = item_no
            
            self.table.setItem(row, 0, item_no)
            self.table.setItem(row, 1, create_item(t))
            self.table.setItem(row, 2, create_item(src_ip))
            self.table.setItem(row, 3, create_item(dst_ip))
            self.table.setItem(row, 4, create_item(geo_str))
            self.table.setItem(row, 5, create_item(proto))
            self.table.setItem(row, 6, create_item(length))
            self.table.setItem(row, 7, create_item(info_str, info_dict))
            self.table.setItem(row, 8, create_item(f"{threat_score:.1f}%"))
            self.table.setItem(row, 9, create_item(severity))
            
            self._color_row(row, proto, severity)
            
            # Update Proto counts
            if proto in self.proto_counts: self.proto_counts[proto] += 1
            else: self.proto_counts['OTHER'] += 1
            
            self.proto_bg.setOpts(height=[self.proto_counts['TCP'], self.proto_counts['UDP'], self.proto_counts['ICMP'], self.proto_counts['OTHER']])
            
            # Apply active filter if one exists
            query = self.filter_box.text().lower()
            if query:
                match = any(query in self.table.item(row, c).text().lower() for c in range(10))
                self.table.setRowHidden(row, not match)
                
            self.table.scrollToBottom()
            
            if self.table.rowCount() > 1000:
                first_item = self.table.item(0, 0)
                if first_item:
                    f_id = first_item.data(Qt.UserRole)
                    if f_id in self.flow_rows:
                        del self.flow_rows[f_id]
                self.table.removeRow(0)
        
    def _color_row(self, row, proto, severity):
        bg_color = QColor('#0F172A') # Slate 900
        text_color = QColor('#cbd5e1')
        
        if proto == 'TCP': bg_color = QColor('#1E293B') # Slate 800
        elif proto == 'UDP': bg_color = QColor('#0F172A')
        elif proto == 'ICMP': bg_color = QColor('#334155') # Slate 700
            
        brush_bg = QBrush(bg_color)
        brush_fg = QBrush(text_color)
        
        severity = str(severity).strip().upper()
        
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(brush_bg)
                
                # Default foreground for all columns except severity
                if col != 9:
                    item.setForeground(brush_fg)
                else:
                    # Severity column text color
                    if severity == 'HIGH':
                        item.setForeground(QBrush(QColor('#EF4444'))) # Red
                        font = QFont("Consolas", 10, QFont.Bold)
                        item.setFont(font)
                    elif severity == 'MEDIUM':
                        item.setForeground(QBrush(QColor('#F59E0B'))) # Orange
                        font = QFont("Consolas", 10, QFont.Bold)
                        item.setFont(font)
                    else:
                        item.setForeground(QBrush(QColor('#10B981'))) # Green
