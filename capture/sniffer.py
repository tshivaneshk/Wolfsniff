import threading
import collections
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, conf, Ether
from scapy.utils import wrpcap
from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from capture.wolfcap_ctypes import NativeCaptureEngine
    USE_NATIVE = True
except Exception as e:
    USE_NATIVE = False
    logger.warning(f"Native Capture Engine not available: {e}. Falling back to Scapy.")

class PacketSniffer(threading.Thread):
    def __init__(self, packet_callback, iface=None, offline_file=None):
        super().__init__()
        self.daemon = True
        
        if USE_NATIVE:
            self.engine = NativeCaptureEngine(packet_callback, iface, offline_file)
            logger.info("Using High-Speed Native C++ Capture Engine (ctypes over wpcap.dll)")
        else:
            self.engine = ScapyCaptureEngine(packet_callback, iface, offline_file)
            logger.info("Using Scapy Fallback Engine")

    @staticmethod
    def get_interfaces():
        try:
            return [iface.name for iface in conf.ifaces.values()]
        except Exception as e:
            logger.error(f"Error enumerating interfaces: {e}")
            return []

    def stop(self):
        self.engine.stop()

    def save_pcap(self, filename):
        return self.engine.save_pcap(filename)

    def export_flow_pcap(self, flow_data, filename):
        return self.engine.export_flow_pcap(flow_data, filename)

    def run(self):
        self.engine.start()
        self.engine.join()


class ScapyCaptureEngine(threading.Thread):
    def __init__(self, packet_callback, iface=None, offline_file=None):
        super().__init__()
        self.packet_callback = packet_callback
        self.iface = iface
        self.offline_file = offline_file
        self.stop_event = threading.Event()
        self.daemon = True
        
        self.packet_buffer = collections.deque(maxlen=100000)
        self.buffer_lock = threading.Lock()

    def stop(self):
        self.stop_event.set()

    def save_pcap(self, filename):
        try:
            with self.buffer_lock:
                pkts = list(self.packet_buffer)
            wrpcap(filename, pkts)
            logger.info(f"Saved {len(self.packet_buffer)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save PCAP: {e}")
            return False

    def export_flow_pcap(self, flow_data, filename):
        src_ip = flow_data.get('src_ip')
        dst_ip = flow_data.get('dst_ip')
        src_port = flow_data.get('src_port')
        dst_port = flow_data.get('dst_port')
        
        from scapy.all import IP, TCP, UDP
        
        filtered = []
        with self.buffer_lock:
            pkts = list(self.packet_buffer)
        for pkt in pkts:
            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                
                if ip_src == src_ip and ip_dst == dst_ip:
                    if TCP in pkt and pkt[TCP].sport == src_port and pkt[TCP].dport == dst_port:
                        filtered.append(pkt)
                    elif UDP in pkt and pkt[UDP].sport == src_port and pkt[UDP].dport == dst_port:
                        filtered.append(pkt)
                elif ip_src == dst_ip and ip_dst == src_ip:
                    if TCP in pkt and pkt[TCP].sport == dst_port and pkt[TCP].dport == src_port:
                        filtered.append(pkt)
                    elif UDP in pkt and pkt[UDP].sport == dst_port and pkt[UDP].dport == src_port:
                        filtered.append(pkt)
                        
        if not filtered:
            return False
            
        try:
            wrpcap(filename, filtered)
            return True
        except Exception as e:
            logger.error(f"Failed to export flow pcap: {e}")
            return False

    def _process_packet(self, packet):
        if self.stop_event.is_set():
            return
            
        with self.buffer_lock:
            self.packet_buffer.append(packet)
            
        try:
            self.packet_callback(packet)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def run(self):
        logger.info(f"Starting Scapy capture on interface: {self.iface or 'default'} (Offline: {self.offline_file})")
        try:
            sniff(
                iface=self.iface if not self.offline_file else None,
                offline=self.offline_file,
                prn=self._process_packet,
                store=False,
                promisc=True,
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Packet sniffer failed: {e}")
        logger.info("Scapy capture stopped.")
