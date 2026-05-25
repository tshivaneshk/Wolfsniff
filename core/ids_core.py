import time
import threading
import uuid
from PySide6.QtCore import QObject, Signal

from capture.sniffer import PacketSniffer
from flows.flow_engine import FlowEngine
from flows.feature_extractor import FeatureExtractor
from ml.model_manager import ModelManager
from database.db_manager import DatabaseManager
from core.geoip import GeoIPManager
from core.rule_engine import RuleEngine
from core.threat_intel import ThreatIntelManager
from core.profiler import AdaptiveProfiler
from core.ja3 import MALICIOUS_JA3
from utils.logger import get_logger

logger = get_logger(__name__)

class IDSCore(QObject):
    # Signals for GUI updates
    alert_triggered = Signal(dict)
    flow_processed = Signal(dict)
    stats_updated = Signal(dict)
    capture_finished = Signal()
    
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.ml_manager = ModelManager()
        self.geoip = GeoIPManager()
        self.rule_engine = RuleEngine()
        self.threat_intel = ThreatIntelManager()
        self.profiler = AdaptiveProfiler()
        self.flow_engine = FlowEngine(flush_callback=self._handle_flushed_flow)
        
        self.sniffer = None
        self.policy = "balanced"
        
        self.running = False
        self.monitor_thread = None
        
    def set_policy(self, policy):
        self.policy = policy

    def start_capture(self, iface=None, policy="balanced", offline_file=None):
        if self.running: return
        self.policy = policy
        self.running = True
        
        self.sniffer = PacketSniffer(
            packet_callback=self.flow_engine.process_packet,
            iface=iface,
            offline_file=offline_file
        )
        self.sniffer.start()
        
        # Start flow expiration daemon
        self.monitor_thread = threading.Thread(target=self._flow_monitor_daemon, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"IDS Core started with policy {policy} on interface {iface or 'default'}")
        
    def stop_capture(self):
        self.running = False
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.join(timeout=2.0)
            
        # Flush remaining flows
        self.flow_engine.flush_all()
        logger.info("IDS Core stopped.")

    def clear_stats(self):
        self.db.clear_all()
        self.stats = {'total_flows': 0, 'total_alerts': 0}
        self.stats_updated.emit(self.stats)

    def load_rules(self, file_path):
        return self.rule_engine.load_rules(file_path)

    def save_pcap(self, filename):
        if self.sniffer:
            return self.sniffer.save_pcap(filename)
        return False

    def _process_and_emit_flow(self, flow, features_dict, is_live=False):
        prob, severity, action, explanation, reasons, activities, recommendations = self.ml_manager.evaluate_flow(features_dict, policy=self.policy)
        
        # Adaptive Profiling (Dynamic Thresholding)
        self.profiler.update(prob)
        z_score = self.profiler.get_z_score(prob)
        
        if z_score > 3.0 and prob > 0.4:
            if severity == "LOW": severity = "MEDIUM"
            elif severity == "MEDIUM": severity = "HIGH"
            explanation = "Z-Score Anomaly: " + explanation
            reasons.append(f"Statistically significant deviation from baseline (Z: {z_score:.2f})")
            
        # JA3 TLS Fingerprinting
        ja3 = features_dict.get('ja3_hash')
        if ja3 and ja3 in MALICIOUS_JA3:
            prob = 0.99
            severity = "CRITICAL"
            explanation = f"Encrypted Threat Detected: {MALICIOUS_JA3[ja3]}"
            reasons.append(f"Malicious JA3 Fingerprint: {ja3}")
            activities.append(f"Command & Control C2 Traffic")
            recommendations.append("Immediately isolate host and terminate connection")

        geo = self.geoip.lookup(flow.dst_ip)
        
        flow_data = features_dict.copy()
        flow_data.update({
            'src_ip': flow.src_ip, 'dst_ip': flow.dst_ip,
            'src_port': flow.src_port, 'dst_port': flow.dst_port,
            'protocol': flow.protocol, 'timestamp': flow.start_time
        })
        
        rule_match = self.rule_engine.match_flow(flow_data)
        if rule_match:
            prob = 1.0
            severity = "HIGH"
            explanation = f"Signature Match: {rule_match}"
            if isinstance(reasons, list): reasons.append(f"Custom Rule: {rule_match}")
            
        flow_data.update({
            'threat_score': prob, 'severity': severity, 'explanation': explanation,
            'reasons': reasons, 'activities': activities, 'recommendations': recommendations,
            'geo_country': geo['country'], 'geo_isp': geo['isp'],
            'is_live': is_live
        })

        if is_live:
            flow_key = f"live_{flow.src_ip}_{flow.dst_ip}_{flow.src_port}_{flow.dst_port}_{flow.protocol}"
            flow_data['id'] = flow_key
            self.flow_processed.emit(flow_data)
            
            # FAST ALERTING: trigger alerts on live flows if severity escalates
            if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
                if getattr(flow, 'alerted_severity', 'LOW') != severity:
                    flow.alerted_severity = severity
                    alert_data = {
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'flow_id': flow_key,
                        'src_ip': flow.src_ip, 'dst_ip': flow.dst_ip,
                        'src_port': flow.src_port, 'dst_port': flow.dst_port,
                        'protocol': flow.protocol,
                        'threat_score': prob,
                        'severity': severity,
                        'explanation': explanation,
                        'threat_intel': flow_data.get('threat_intel'),
                        'raw_flow': flow_data
                    }
                    self.db.insert_alert(alert_data)
                    self.stats_updated.emit(self.db.get_stats())
                    self.alert_triggered.emit(alert_data)
        else:
            # Threat Intel integration only on flushed flows
            if severity != 'LOW':
                intel = self.threat_intel.query_ip(flow.dst_ip)
                flow_data['threat_intel'] = str(intel)
                flow_id = self.db.insert_flow(flow_data)
                flow_data['id'] = flow_id
            else:
                flow_data['threat_intel'] = None
                flow_id = None
                flow_data['id'] = str(uuid.uuid4())

            self.flow_processed.emit(flow_data)
            
            if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
                if getattr(flow, 'alerted_severity', 'LOW') != severity:
                    alert_data = {
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'flow_id': flow_id,
                        'src_ip': flow.src_ip, 'dst_ip': flow.dst_ip,
                        'src_port': flow.src_port, 'dst_port': flow.dst_port,
                        'protocol': flow.protocol,
                        'threat_score': prob,
                        'severity': severity,
                        'explanation': explanation,
                        'threat_intel': flow_data.get('threat_intel'),
                        'raw_flow': flow_data
                    }
                    self.db.insert_alert(alert_data)
                    self.stats_updated.emit(self.db.get_stats())
                    self.alert_triggered.emit(alert_data)
                else:
                    # Already alerted during live. Just update the DB with threat intel and real flow_id
                    self.db.update_live_alert(
                        flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol,
                        flow_id, flow_data.get('threat_intel')
                    )

    def _flow_monitor_daemon(self):
        while self.running:
            time.sleep(1.0)  # Check every 1 second for live updates
            
            # Live evaluate active flows to create Wireshark-like stream
            active_snapshots = self.flow_engine.get_active_flows_snapshot()
            for flow, features_dict in active_snapshots:
                self._process_and_emit_flow(flow, features_dict, is_live=True)

            self.flow_engine.check_timeouts()
            
            # Periodically emit stats
            stats = self.db.get_stats()
            if stats:
                self.stats_updated.emit(stats)
                
            if self.sniffer and not self.sniffer.is_alive():
                self.flow_engine.flush_all()
                self.running = False
                self.capture_finished.emit()
                break

    def _handle_flushed_flow(self, flow, features_dict):
        """Called by FlowEngine when a flow expires."""
        self._process_and_emit_flow(flow, features_dict, is_live=False)
