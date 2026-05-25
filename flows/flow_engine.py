import time
import threading
from scapy.all import IP, TCP, UDP, ICMP
from flows.feature_extractor import FeatureExtractor
from utils.config import FLOW_TIMEOUT_SEC, MAX_FLOWS_IN_MEMORY
from utils.logger import get_logger

logger = get_logger(__name__)

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, packet_time):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = float(packet_time)
        self.end_time = self.start_time
        
        self.src_packets = 0
        self.dst_packets = 0
        self.src_bytes = 0
        self.dst_bytes = 0
        
        self.src_ttl = 0
        self.dst_ttl = 0
        
        self.src_retransmits = 0
        self.dst_retransmits = 0
        
        self.src_interpacket_time = 0
        self.dst_interpacket_time = 0
        self.src_jitter = 0
        self.dst_jitter = 0
        
        self.src_win = 0
        self.dst_win = 0
        self.src_tcp_base = 0
        self.dst_tcp_base = 0
        self.tcprtt = 0
        self.synack = 0
        self.ackdat = 0
        
        self.trans_depth = 0
        self.response_body_len = 0
        
        self.ftp_login = False
        self.ja3_hash = None
        self.flags = []
        
        self.service = self._guess_service(src_port, dst_port)
        self.state = 'INT' if protocol != 'tcp' else 'CON'
        
        # Internal state
        self._last_src_time = None
        self._last_dst_time = None
        self._src_seq_seen = set()
        self._dst_seq_seen = set()
        self._syn_time = None
        self._synack_time = None

        from core.ja3 import extract_ja3
        self._extract_ja3 = extract_ja3

    def _guess_service(self, sport, dport):
        ports = {sport, dport}
        if 80 in ports or 443 in ports: return 'http'
        if 53 in ports: return 'dns'
        if 21 in ports or 20 in ports: return 'ftp'
        if 22 in ports: return 'ssh'
        if 25 in ports or 465 in ports or 587 in ports: return 'smtp'
        if 110 in ports or 995 in ports: return 'pop3'
        if 143 in ports or 993 in ports: return 'imap'
        return 'unknown'

    def update(self, packet, is_src):
        self.end_time = float(packet.time)
        pkt_len = len(packet)
        
        if IP in packet:
            ttl = packet[IP].ttl
            if is_src: self.src_ttl = ttl
            else: self.dst_ttl = ttl
            
        if TCP in packet:
            tcp = packet[TCP]

        if TCP in packet:
            if not self.ja3_hash and packet[TCP].dport == 443:
                self.ja3_hash = self._extract_ja3(packet)

            seq = tcp.seq
            
            if is_src:
                self.src_win = tcp.window
                if self.src_packets == 0: self.src_tcp_base = seq
                if seq in self._src_seq_seen: self.src_retransmits += 1
                self._src_seq_seen.add(seq)
                
                # TCP state tracking
                if tcp.flags.S and not tcp.flags.A:
                    self._syn_time = self.end_time
                    self.state = 'REQ'
                if tcp.flags.A and self._synack_time and not self.tcprtt:
                    self.ackdat = self.end_time - self._synack_time
                    self.tcprtt = self.synack + self.ackdat
                    self.state = 'CON'
                if tcp.flags.F:
                    self.state = 'FIN'
                if tcp.flags.R:
                    self.state = 'RST'
                    
            else:
                self.dst_win = tcp.window
                if self.dst_packets == 0: self.dst_tcp_base = seq
                if seq in self._dst_seq_seen: self.dst_retransmits += 1
                self._dst_seq_seen.add(seq)
                
                if tcp.flags.S and tcp.flags.A and self._syn_time and not self.synack:
                    self.synack = self.end_time - self._syn_time
                    self._synack_time = self.end_time
                    
        # Update rates and timing
        if is_src:
            self.src_packets += 1
            self.src_bytes += pkt_len
            if self._last_src_time:
                diff = self.end_time - self._last_src_time
                if self.src_packets > 2:
                    self.src_jitter = (self.src_jitter * (self.src_packets-2) + abs(diff - self.src_interpacket_time)) / (self.src_packets - 1)
                self.src_interpacket_time = (self.src_interpacket_time * (self.src_packets-2) + diff) / (self.src_packets - 1) if self.src_packets > 1 else 0
            self._last_src_time = self.end_time
        else:
            self.dst_packets += 1
            self.dst_bytes += pkt_len
            if self._last_dst_time:
                diff = self.end_time - self._last_dst_time
                if self.dst_packets > 2:
                    self.dst_jitter = (self.dst_jitter * (self.dst_packets-2) + abs(diff - self.dst_interpacket_time)) / (self.dst_packets - 1)
                self.dst_interpacket_time = (self.dst_interpacket_time * (self.dst_packets-2) + diff) / (self.dst_packets - 1) if self.dst_packets > 1 else 0
            self._last_dst_time = self.end_time

class FlowEngine:
    def __init__(self, flush_callback):
        self.active_flows = {}
        self.flow_history = []
        self.lock = threading.Lock()
        self.flush_callback = flush_callback
        self.virtual_time = 0.0
        self._last_timeout_check = 0.0
        
    def _get_flow_key(self, packet):
        if IP not in packet:
            return None
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto_str = 'unknown'
        sport, dport = 0, 0
        
        if TCP in packet:
            proto_str = 'tcp'
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            proto_str = 'udp'
            sport, dport = packet[UDP].sport, packet[UDP].dport
        elif ICMP in packet:
            proto_str = 'icmp'
            
        key1 = (src, dst, sport, dport, proto_str)
        key2 = (dst, src, dport, sport, proto_str)
        return key1, key2, proto_str

    def _get_expired_flows_locked(self):
        current_time = self.virtual_time if self.virtual_time > 0 else time.time()
        expired = []
        for key, flow in list(self.active_flows.items()):
            if current_time - flow.end_time > FLOW_TIMEOUT_SEC:
                expired.append(key)
        
        expired_flows = []
        for key in expired:
            expired_flows.append(self.active_flows.pop(key))
            
        history_snapshot = list(self.flow_history)
        return expired_flows, history_snapshot

    def process_packet(self, packet):
        keys = self._get_flow_key(packet)
        if not keys: return
        key_fwd, key_rev, proto_str = keys
        
        expired_flows_to_flush = []
        history_snapshot = []
        
        with self.lock:
            pkt_time = float(packet.time)
            self.virtual_time = max(self.virtual_time, pkt_time)
            
            if self.virtual_time - self._last_timeout_check >= 1.0:
                self._last_timeout_check = self.virtual_time
                expired_flows_to_flush, history_snapshot = self._get_expired_flows_locked()
                
            if key_fwd in self.active_flows:
                flow = self.active_flows[key_fwd]
                flow.update(packet, is_src=True)
            elif key_rev in self.active_flows:
                flow = self.active_flows[key_rev]
                flow.update(packet, is_src=False)
            else:
                src_ip, dst_ip, src_port, dst_port, _ = key_fwd
                flow = Flow(src_ip, dst_ip, src_port, dst_port, proto_str, float(packet.time))
                flow.update(packet, is_src=True)
                self.active_flows[key_fwd] = flow
                self.flow_history.append(flow)
                if len(self.flow_history) > MAX_FLOWS_IN_MEMORY:
                    self.flow_history.pop(0)
                    
        for flow in expired_flows_to_flush:
            features_dict = FeatureExtractor.extract_features(flow, history_snapshot)
            features_dict['ja3_hash'] = flow.ja3_hash
            self.flush_callback(flow, features_dict)

    def check_timeouts(self):
        expired_flows = []
        with self.lock:
            expired_flows, history_snapshot = self._get_expired_flows_locked()
            
        for flow in expired_flows:
            features_dict = FeatureExtractor.extract_features(flow, history_snapshot)
            features_dict['ja3_hash'] = flow.ja3_hash
            # Pass back to controller for ML inference
            self.flush_callback(flow, features_dict)

    def flush_all(self):
        expired_flows = []
        with self.lock:
            for key, flow in list(self.active_flows.items()):
                expired_flows.append(flow)
            history_snapshot = list(self.flow_history)
            self.active_flows.clear()
            
        for flow in expired_flows:
            features_dict = FeatureExtractor.extract_features(flow, history_snapshot)
            features_dict['ja3_hash'] = flow.ja3_hash
            self.flush_callback(flow, features_dict)

    def get_active_flows_snapshot(self):
        snapshots = []
        with self.lock:
            active_flows_copy = list(self.active_flows.values())
            history_snapshot = list(self.flow_history)
            
        for flow in active_flows_copy:
            features = FeatureExtractor.extract_features(flow, history_snapshot)
            snapshots.append((flow, features))
        return snapshots
