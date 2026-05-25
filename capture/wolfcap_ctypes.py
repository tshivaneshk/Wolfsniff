import ctypes
import ctypes.util
import struct
import socket
import threading
import collections
from utils.logger import get_logger

logger = get_logger(__name__)

# --- wpcap.dll constants and structs ---
PCAP_ERRBUF_SIZE = 256

class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_long),
        ("caplen", ctypes.c_uint32),
        ("len", ctypes.c_uint32)
    ]

# Callback signature: void pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
PCAP_HANDLER = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(pcap_pkthdr), ctypes.POINTER(ctypes.c_ubyte))

class NativeCaptureEngine(threading.Thread):
    def __init__(self, packet_callback, iface=None, offline_file=None):
        super().__init__()
        self.packet_callback = packet_callback
        self.iface = iface
        self.offline_file = offline_file
        self.stop_event = threading.Event()
        self.daemon = True
        
        self.packet_buffer = collections.deque(maxlen=100000)
        self.buffer_lock = threading.Lock()
        
        # Load DLL
        wpcap_path = ctypes.util.find_library("wpcap")
        if not wpcap_path:
            import os
            if os.path.exists(r"C:\Windows\System32\wpcap.dll"):
                wpcap_path = r"C:\Windows\System32\wpcap.dll"
            else:
                raise RuntimeError("wpcap.dll not found. Npcap/WinPcap is required.")
        self.wpcap = ctypes.CDLL(wpcap_path)
        
        self.wpcap.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        self.wpcap.pcap_open_live.restype = ctypes.c_void_p
        
        self.wpcap.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.wpcap.pcap_open_offline.restype = ctypes.c_void_p
        
        self.wpcap.pcap_loop.argtypes = [ctypes.c_void_p, ctypes.c_int, PCAP_HANDLER, ctypes.POINTER(ctypes.c_ubyte)]
        self.wpcap.pcap_loop.restype = ctypes.c_int
        
        self.wpcap.pcap_breakloop.argtypes = [ctypes.c_void_p]
        self.wpcap.pcap_close.argtypes = [ctypes.c_void_p]
        
        self.handle = None
        self._c_callback = PCAP_HANDLER(self._packet_handler)
        
        self._setup_scapy_shims()

    def _setup_scapy_shims(self):
        class FakeLayer:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)
                
        class FakePacket:
            def haslayer(self, layer_type):
                try:
                    return layer_type.__name__ in self._layers
                except Exception:
                    return False
                    
            def __init__(self, time, layers, raw):
                self.time = time
                self._layers = layers
                self.raw_bytes = raw
                
            def __contains__(self, layer_type):
                return layer_type.__name__ in self._layers
                
            def __getitem__(self, layer_type):
                return self._layers[layer_type.__name__]
                
            def __bytes__(self):
                return self.raw_bytes
                
            def __len__(self):
                return len(self.raw_bytes)
        
        self.FakePacket = FakePacket
        self.FakeLayer = FakeLayer
        
        from scapy.all import IP, TCP, UDP, ICMP
        self.IP_cls = IP
        self.TCP_cls = TCP
        self.UDP_cls = UDP
        self.ICMP_cls = ICMP

    def _packet_handler(self, user, header_ptr, packet_ptr):
        if self.stop_event.is_set():
            if self.handle:
                self.wpcap.pcap_breakloop(self.handle)
            return

        caplen = header_ptr.contents.caplen
        if caplen < 34:
            return
            
        raw_bytes = bytes(packet_ptr[:caplen])
        time_sec = header_ptr.contents.tv_sec
        time_usec = header_ptr.contents.tv_usec
        pkt_time = time_sec + (time_usec / 1000000.0)

        ethertype = struct.unpack("!H", raw_bytes[12:14])[0]
        
        if ethertype == 0x0800:
            ip_header = raw_bytes[14:34]
            ihl = (ip_header[0] & 0x0F) * 4
            ttl = ip_header[8]
            protocol = ip_header[9]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            
            layers = {
                "IP": self.FakeLayer(src=src_ip, dst=dst_ip, ttl=ttl, proto=protocol)
            }
            
            payload_offset = 14 + ihl
            if protocol == 6:
                if caplen >= payload_offset + 20:
                    tcp_header = raw_bytes[payload_offset:payload_offset+20]
                    sport, dport, seq, ack, offset_reserved, flags, window, chk, urg = struct.unpack("!HHIIBBHHH", tcp_header[:20])
                    dataofs = (offset_reserved >> 4) * 4
                    
                    class FakeFlags:
                        def __init__(self, f):
                            self.value = f
                            self.F = bool(f & 0x01)
                            self.S = bool(f & 0x02)
                            self.R = bool(f & 0x04)
                            self.P = bool(f & 0x08)
                            self.A = bool(f & 0x10)
                            self.U = bool(f & 0x20)
                    
                    layers["TCP"] = self.FakeLayer(sport=sport, dport=dport, seq=seq, ack=ack, window=window, flags=FakeFlags(flags), dataofs=dataofs)
            elif protocol == 17:
                if caplen >= payload_offset + 8:
                    udp_header = raw_bytes[payload_offset:payload_offset+8]
                    sport, dport, udp_len, udp_chk = struct.unpack("!HHHH", udp_header)
                    layers["UDP"] = self.FakeLayer(sport=sport, dport=dport, len=udp_len)
            elif protocol == 1:
                if caplen >= payload_offset + 4:
                    icmp_header = raw_bytes[payload_offset:payload_offset+4]
                    icmptype, icmpcode, icmpchk = struct.unpack("!BBH", icmp_header)
                    layers["ICMP"] = self.FakeLayer(type=icmptype, code=icmpcode)
                    
            pkt = self.FakePacket(pkt_time, layers, raw_bytes)
            
            with self.buffer_lock:
                self.packet_buffer.append(pkt)
                
            try:
                self.packet_callback(pkt)
            except Exception:
                pass

    def run(self):
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        
        if self.offline_file:
            logger.info(f"[C++ Native Engine] Opening offline file: {self.offline_file}")
            self.handle = self.wpcap.pcap_open_offline(self.offline_file.encode('utf-8'), errbuf)
        else:
            iface_str = self.iface
            
            # Resolve friendly name (e.g., 'Wi-Fi') to NPF Device name
            if iface_str and not iface_str.startswith("\\Device\\NPF_"):
                from scapy.all import conf
                for k, v in conf.ifaces.items():
                    if v.name == iface_str or v.description == iface_str:
                        iface_str = k
                        break
                        
            if not iface_str or iface_str == "Auto-Detect":
                from scapy.all import conf
                # Use Scapy's default active route interface
                default_iface = conf.iface
                iface_str = default_iface.name
                for k, v in conf.ifaces.items():
                    if v.name == iface_str or v.description == iface_str:
                        iface_str = k
                        break

            logger.info(f"[C++ Native Engine] Opening live interface: {iface_str} (from {self.iface})")
            self.handle = self.wpcap.pcap_open_live(
                iface_str.encode('utf-8'),
                65536,
                1,
                100,
                errbuf
            )
            
        if not self.handle:
            logger.error(f"[C++ Native Engine] Failed to open capture: {errbuf.value.decode('utf-8', 'ignore')}")
            return
            
        logger.info("[C++ Native Engine] Starting capture loop...")
        self.wpcap.pcap_loop(self.handle, 0, self._c_callback, None)
        
        if self.handle:
            self.wpcap.pcap_close(self.handle)
            self.handle = None
            
        logger.info("[C++ Native Engine] Capture stopped.")

    def stop(self):
        self.stop_event.set()
        if self.handle:
            self.wpcap.pcap_breakloop(self.handle)

    def save_pcap(self, filename):
        from scapy.utils import RawPcapWriter
        with self.buffer_lock:
            pkts = list(self.packet_buffer)
        
        try:
            with RawPcapWriter(filename, append=False, sync=True, linktype=1) as pcap:
                pcap._write_header(None)
                for p in pkts:
                    if hasattr(p, 'raw_bytes'):
                        t = p.time
                        sec = int(t)
                        usec = int((t - sec) * 1000000)
                        pcap._write_packet(p.raw_bytes, linktype=1, sec=sec, usec=usec)
            return True
        except Exception as e:
            logger.error(f"Failed to save pcap: {e}")
            return False

    def export_flow_pcap(self, flow_data, filename):
        src_ip = flow_data.get('src_ip')
        dst_ip = flow_data.get('dst_ip')
        src_port = flow_data.get('src_port')
        dst_port = flow_data.get('dst_port')
        
        from scapy.all import IP, TCP, UDP
        from scapy.utils import RawPcapWriter
        
        filtered = []
        with self.buffer_lock:
            pkts = list(self.packet_buffer)
            
        for pkt in pkts:
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                
                if ip_src == src_ip and ip_dst == dst_ip:
                    if pkt.haslayer(TCP) and pkt[TCP].sport == src_port and pkt[TCP].dport == dst_port:
                        filtered.append(pkt)
                    elif pkt.haslayer(UDP) and pkt[UDP].sport == src_port and pkt[UDP].dport == dst_port:
                        filtered.append(pkt)
                elif ip_src == dst_ip and ip_dst == src_ip:
                    if pkt.haslayer(TCP) and pkt[TCP].sport == dst_port and pkt[TCP].dport == src_port:
                        filtered.append(pkt)
                    elif pkt.haslayer(UDP) and pkt[UDP].sport == dst_port and pkt[UDP].dport == src_port:
                        filtered.append(pkt)
                        
        if not filtered:
            return False
            
        try:
            with RawPcapWriter(filename, append=False, sync=True, linktype=1) as pcap:
                pcap._write_header(None)
                for p in filtered:
                    if hasattr(p, 'raw_bytes'):
                        t = p.time
                        sec = int(t)
                        usec = int((t - sec) * 1000000)
                        pcap._write_packet(p.raw_bytes, linktype=1, sec=sec, usec=usec)
            return True
        except Exception as e:
            logger.error(f"Failed to export flow pcap: {e}")
            return False
