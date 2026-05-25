import pyqtgraph as pg
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtCore import Qt
import numpy as np
from PySide6.QtWidgets import QTabWidget

class TopologyView(QWidget):
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.view = pg.GraphicsLayoutWidget()
        self.view.setBackground('#0F172A')
        self.plot = self.view.addPlot()
        self.plot.hideAxis('left')
        self.plot.hideAxis('bottom')
        self.plot.setMouseEnabled(x=True, y=True)
        
        self.graph = pg.GraphItem()
        self.plot.addItem(self.graph)
        self.graph.scatter.sigClicked.connect(self.on_node_clicked)
        
        # Sidebar
        side_panel = QWidget()
        side_panel.setFixedWidth(300)
        side_panel.setStyleSheet("background-color: #1E293B; border-left: 1px solid #334155;")
        side_layout = QVBoxLayout(side_panel)
        
        self.lbl_selected = QLabel("Selected Node: None")
        self.lbl_selected.setStyleSheet("color: #38BDF8; font-size: 16px; font-weight: bold;")
        self.lbl_selected.setWordWrap(True)
        
        self.lbl_conns = QLabel("Connections: 0")
        self.lbl_conns.setStyleSheet("color: #94A3B8; font-size: 14px;")
        
        lbl_info = QLabel("Active Network Entities")
        lbl_info.setStyleSheet("color: #F8FAFC; font-size: 14px; font-weight: bold; margin-top: 15px;")
        
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["IP Address", "Links"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.setStyleSheet("background-color: #0F172A; color: #CBD5E1; border: none;")
        
        side_layout.addWidget(self.lbl_selected)
        side_layout.addWidget(self.lbl_conns)
        side_layout.addWidget(lbl_info)
        side_layout.addWidget(self.table)
        
        layout.addWidget(self.view, stretch=1)
        layout.addWidget(side_panel, stretch=0)
        
        self.nodes = {}
        self.reverse_nodes = {}
        self.edges = set()
        
    def add_flow(self, flow_data):
        src = flow_data.get('src_ip')
        dst = flow_data.get('dst_ip')
        if not src or not dst: return
        
        self._add_node(src)
        self._add_node(dst)
            
        edge = (self.nodes[src], self.nodes[dst])
        if edge not in self.edges and (edge[1], edge[0]) not in self.edges:
            self.edges.add(edge)
            self._update_graph()
            
    def _add_node(self, ip):
        if ip not in self.nodes:
            idx = len(self.nodes)
            self.nodes[ip] = idx
            self.reverse_nodes[idx] = ip

    def _update_graph(self):
        n = len(self.nodes)
        if n == 0: return
        
        pos_array = np.zeros((n, 2))
        node_ips = list(self.nodes.keys())
        
        for i in range(n):
            if i == 0:
                pos_array[i] = [0, 0]
            else:
                ring = int(np.sqrt(i))
                angle = i * (2 * np.pi / (ring * 4))
                radius = ring * 10
                pos_array[i] = [radius * np.cos(angle), radius * np.sin(angle)]
                
        edges_array = np.array(list(self.edges), dtype=int) if self.edges else np.empty((0, 2), dtype=int)
        
        self.graph.setData(pos=pos_array, adj=edges_array, size=15, 
                           symbolBrush='#0ea5e9', symbolPen='#0284c7', 
                           pen='#334155')
                           
        self.table.setRowCount(0)
        for i, ip in enumerate(node_ips):
            conns = sum(1 for e in self.edges if i in e)
            r = self.table.rowCount()
            self.table.insertRow(r)
            item_ip = QTableWidgetItem(ip)
            item_ip.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            item_conns = QTableWidgetItem(str(conns))
            item_conns.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            
            self.table.setItem(r, 0, item_ip)
            self.table.setItem(r, 1, item_conns)
            
    def on_node_clicked(self, scatter, points):
        if not points: return
        pt = points[0]
        pos = pt.pos()
        
        min_dist = 9999
        closest_idx = -1
        
        n = len(self.nodes)
        for i in range(n):
            if i == 0:
                rx, ry = 0, 0
            else:
                ring = int(np.sqrt(i))
                angle = i * (2 * np.pi / (ring * 4))
                radius = ring * 10
                rx, ry = radius * np.cos(angle), radius * np.sin(angle)
            
            dist = (rx-pos.x())**2 + (ry-pos.y())**2
            if dist < min_dist:
                min_dist = dist
                closest_idx = i
                
        if closest_idx != -1:
            ip = self.reverse_nodes.get(closest_idx, "Unknown")
            conns = sum(1 for e in self.edges if closest_idx in e)
            self.lbl_selected.setText(f"Selected: {ip}")
            self.lbl_conns.setText(f"Connections: {conns}")

    def clear_all(self):
        self.nodes.clear()
        self.reverse_nodes.clear()
        self.edges.clear()
        self.graph.setData(pos=np.empty((0,2)), adj=np.empty((0,2), dtype=int))
        self.table.setRowCount(0)
        self.lbl_selected.setText("Selected Node: None")
        self.lbl_conns.setText("Connections: 0")

class TopologyTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: none; }
            QTabBar::tab { background: #1E293B; color: #94A3B8; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px; }
            QTabBar::tab:selected { background: #0F172A; color: #06B6D4; font-weight: bold; border-bottom: 2px solid #06B6D4; }
        """)
        layout.addWidget(self.tab_widget)
        
        self.live_view = TopologyView()
        self.tab_widget.addTab(self.live_view, "Live Capture")
        
        self.pcap_views = {}
        
    def add_flow(self, flow_data):
        self.live_view.add_flow(flow_data)
        
    def clear_all(self):
        self.live_view.clear_all()
        
    def add_pcap_tab(self, tab_id, core_instance):
        view = TopologyView()
        core_instance.flow_processed.connect(view.add_flow)
        self.tab_widget.addTab(view, tab_id)
        self.pcap_views[tab_id] = view
        
    def remove_pcap_tab(self, tab_id):
        if tab_id in self.pcap_views:
            view = self.pcap_views[tab_id]
            idx = self.tab_widget.indexOf(view)
            if idx != -1:
                self.tab_widget.removeTab(idx)
            view.deleteLater()
            del self.pcap_views[tab_id]
