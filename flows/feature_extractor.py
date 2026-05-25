import time
from utils.logger import get_logger

logger = get_logger(__name__)

class FeatureExtractor:
    @staticmethod
    def extract_features(flow, active_window):
        """
        Extracts 42 ML-compatible features from a Flow object and sliding window history.
        """
        features = {}
        
        # 1. Basic Flow Features
        dur = max(0.000001, flow.end_time - flow.start_time)
        features['dur'] = dur
        features['proto'] = flow.protocol
        features['service'] = flow.service
        features['state'] = flow.state
        
        features['spkts'] = flow.src_packets
        features['dpkts'] = flow.dst_packets
        features['sbytes'] = flow.src_bytes
        features['dbytes'] = flow.dst_bytes
        
        features['rate'] = (flow.src_packets + flow.dst_packets) / dur
        
        features['sttl'] = flow.src_ttl
        features['dttl'] = flow.dst_ttl
        
        features['sload'] = (flow.src_bytes * 8) / dur
        features['dload'] = (flow.dst_bytes * 8) / dur
        
        features['sloss'] = flow.src_retransmits
        features['dloss'] = flow.dst_retransmits
        
        features['sinpkt'] = flow.src_interpacket_time
        features['dinpkt'] = flow.dst_interpacket_time
        
        features['sjit'] = flow.src_jitter
        features['djit'] = flow.dst_jitter
        
        # 2. TCP specific
        features['swin'] = flow.src_win
        features['dwin'] = flow.dst_win
        features['stcpb'] = flow.src_tcp_base
        features['dtcpb'] = flow.dst_tcp_base
        features['tcprtt'] = flow.tcprtt
        features['synack'] = flow.synack
        features['ackdat'] = flow.ackdat
        
        features['smean'] = flow.src_bytes / max(1, flow.src_packets)
        features['dmean'] = flow.dst_bytes / max(1, flow.dst_packets)
        
        features['trans_depth'] = flow.trans_depth
        features['response_body_len'] = flow.response_body_len
        
        # 3. Sliding Window Features (calculated over active_window)
        ct_srv_src = 0
        ct_state_ttl = 0
        ct_dst_ltm = 0
        ct_src_dport_ltm = 0
        ct_dst_sport_ltm = 0
        ct_dst_src_ltm = 0
        ct_ftp_cmd = 0
        ct_flw_http_mthd = 0
        ct_src_ltm = 0
        ct_srv_dst = 0
        
        for w_flow in active_window:
            if w_flow.service == flow.service and w_flow.src_ip == flow.src_ip:
                ct_srv_src += 1
            if w_flow.state == flow.state and w_flow.src_ttl == flow.src_ttl:
                ct_state_ttl += 1
            if w_flow.dst_ip == flow.dst_ip:
                ct_dst_ltm += 1
            if w_flow.src_ip == flow.src_ip and w_flow.dst_port == flow.dst_port:
                ct_src_dport_ltm += 1
            if w_flow.dst_ip == flow.dst_ip and w_flow.src_port == flow.src_port:
                ct_dst_sport_ltm += 1
            if w_flow.src_ip == flow.src_ip and w_flow.dst_ip == flow.dst_ip:
                ct_dst_src_ltm += 1
            if w_flow.src_ip == flow.src_ip:
                ct_src_ltm += 1
            if w_flow.service == flow.service and w_flow.dst_ip == flow.dst_ip:
                ct_srv_dst += 1
            
            if w_flow.service == 'ftp' and 'cmd' in w_flow.flags:
                ct_ftp_cmd += 1
            if w_flow.service == 'http':
                ct_flw_http_mthd += 1
                
        features['ct_srv_src'] = ct_srv_src
        features['ct_state_ttl'] = ct_state_ttl
        features['ct_dst_ltm'] = ct_dst_ltm
        features['ct_src_dport_ltm'] = ct_src_dport_ltm
        features['ct_dst_sport_ltm'] = ct_dst_sport_ltm
        features['ct_dst_src_ltm'] = ct_dst_src_ltm
        features['is_ftp_login'] = 1 if (flow.service == 'ftp' and flow.ftp_login) else 0
        features['ct_ftp_cmd'] = ct_ftp_cmd
        features['ct_flw_http_mthd'] = ct_flw_http_mthd
        features['ct_src_ltm'] = ct_src_ltm
        features['ct_srv_dst'] = ct_srv_dst
        
        features['is_sm_ips_ports'] = 1 if (flow.src_ip == flow.dst_ip and flow.src_port == flow.dst_port) else 0
        
        return features
