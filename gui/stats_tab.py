import pyqtgraph as pg
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout
from PySide6.QtGui import QBrush, QColor
from PySide6.QtCore import Qt

class StatsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        
        self.lbl_title = QLabel("Database Statistics & Deep Telemetry")
        self.lbl_title.setStyleSheet("font-size: 24px; font-weight: bold; color: #06B6D4; padding-bottom: 20px;")
        
        numbers_layout = QHBoxLayout()
        self.card1, self.lbl_total_flows = self._create_number_card("Total Flows Logged", "0", "#3B82F6")
        self.card2, self.lbl_total_alerts = self._create_number_card("Total Alerts Generated", "0", "#F43F5E")
        self.card3, self.lbl_high_sev = self._create_number_card("High Severity Threats", "0", "#9F1239")
        numbers_layout.addWidget(self.card1)
        numbers_layout.addWidget(self.card2)
        numbers_layout.addWidget(self.card3)
        
        # Grid Dashboard for Telemetry
        grid_layout = QGridLayout()
        
        self.panel_attackers = self._create_panel("Top Unique Attacker IPs")
        self.panel_ports = self._create_panel("Top Targeted Ports")
        self.panel_targets = self._create_panel("Unique Targeted IPs")
        
        grid_layout.addWidget(self.panel_attackers[0], 0, 0)
        grid_layout.addWidget(self.panel_ports[0], 0, 1)
        grid_layout.addWidget(self.panel_targets[0], 1, 0, 1, 2)
        
        graphs_layout = QHBoxLayout()
        self.proto_chart = pg.PlotWidget(title="Protocol Dist.")
        self.proto_chart.setBackground('#1E293B')
        self.proto_chart.setMouseEnabled(x=False, y=False)
        self.proto_chart.setMaximumHeight(200)
        
        self.sev_chart = pg.PlotWidget(title="Severity Dist.")
        self.sev_chart.setBackground('#1E293B')
        self.sev_chart.setMouseEnabled(x=False, y=False)
        self.sev_chart.setMaximumHeight(200)
        
        graphs_layout.addWidget(self.proto_chart)
        graphs_layout.addWidget(self.sev_chart)
        
        self.layout.addWidget(self.lbl_title)
        self.layout.addLayout(numbers_layout)
        self.layout.addLayout(grid_layout, stretch=1)
        self.layout.addLayout(graphs_layout)
        
        self.colors = ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4']
        
    def _create_number_card(self, title, val, color):
        card = QWidget()
        card.setStyleSheet(f"background-color: #1E293B; border-radius: 8px; border-left: 4px solid {color};")
        v = QVBoxLayout(card)
        t = QLabel(title)
        t.setStyleSheet("color: #94A3B8; font-size: 14px; font-weight: bold;")
        v.addWidget(t)
        lbl_val = QLabel(val)
        lbl_val.setStyleSheet(f"color: {color}; font-size: 36px; font-weight: bold;")
        v.addWidget(lbl_val)
        return card, lbl_val
        
    def _create_panel(self, title):
        card = QWidget()
        card.setStyleSheet("background-color: #0F172A; border-radius: 8px; border: 1px solid #334155;")
        v = QVBoxLayout(card)
        t = QLabel(title)
        t.setStyleSheet("color: #38BDF8; font-size: 16px; font-weight: bold; border: none;")
        v.addWidget(t)
        content = QLabel("No Data")
        content.setStyleSheet("color: #CBD5E1; font-size: 14px; border: none;")
        content.setAlignment(Qt.AlignTop)
        v.addWidget(content, stretch=1)
        return card, content

    def update_stats(self, stats_data):
        if not stats_data: return
        
        total = stats_data.get('total_flows', 0)
        self.lbl_total_flows.setText(f"{total:,}")
        
        protocols = stats_data.get('protocols', {})
        severities = stats_data.get('severities', {})
        
        tot_alerts = sum(severities.values())
        self.lbl_total_alerts.setText(f"{tot_alerts:,}")
        self.lbl_high_sev.setText(f"{severities.get('HIGH', 0):,}")
        
        usrc = stats_data.get('unique_src', 0)
        udst = stats_data.get('unique_dst', 0)
        top_ports = stats_data.get('top_ports', [])
        
        self.panel_attackers[1].setText(f"Total Unique Attackers: {usrc:,}")
        self.panel_targets[1].setText(f"Total Unique Targets: {udst:,}")
        
        port_txt = ""
        for i, (p, c) in enumerate(top_ports):
            port_txt += f"<b>{i+1}. Port {p}</b> - {c:,} attacks<br>"
        self.panel_ports[1].setText(port_txt if port_txt else "No Data")
            
        if protocols:
            self.proto_chart.clear()
            items = list(protocols.items())
            for i, (k, v) in enumerate(items):
                bg = pg.BarGraphItem(x=[i], height=[v], width=0.6, brush=self.colors[i % len(self.colors)])
                self.proto_chart.addItem(bg)
            axis = self.proto_chart.getAxis('bottom')
            axis.setTicks([[(i, str(k).upper()) for i, (k, v) in enumerate(items)]])
            
        if severities:
            self.sev_chart.clear()
            items = list(severities.items())
            for i, (k, v) in enumerate(items):
                bg = pg.BarGraphItem(x=[i], height=[v], width=0.6, brush=self.colors[-(i+1) % len(self.colors)])
                self.sev_chart.addItem(bg)
            axis = self.sev_chart.getAxis('bottom')
            axis.setTicks([[(i, str(k).upper()) for i, (k, v) in enumerate(items)]])
