import urllib.request
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import threading

class DNSResolver:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DNSResolver, cls).__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self):
        self.cache = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        # Pre-populate common local IPs
        self.cache['127.0.0.1'] = 'localhost'
        self.cache['0.0.0.0'] = '0.0.0.0'

    def resolve(self, ip, callback=None):
        if ip in self.cache:
            if callback:
                callback(ip, self.cache[ip])
            return self.cache[ip]
        
        # Mark as pending to avoid redundant concurrent queries
        self.cache[ip] = ip 
        
        def _resolve_task():
            try:
                # gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
                host, _, _ = socket.gethostbyaddr(ip)
                
                # Fetch Geo-IP for external addresses
                geo_info = ""
                if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.') or ip == '127.0.0.1'):
                    try:
                        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=country,city,status", headers={'User-Agent': 'Mozilla/5.0'})
                        with urllib.request.urlopen(req, timeout=1) as response:
                            data = json.loads(response.read().decode())
                            if data.get("status") == "success":
                                geo_info = f" [{data.get('city', '')}, {data.get('country', '')}]"
                    except Exception:
                        pass
                        
                final_string = host + geo_info
                self.cache[ip] = final_string
                if callback:
                    callback(ip, final_string)
            except Exception:
                self.cache[ip] = ip # fallback to raw IP if resolution fails

        self.executor.submit(_resolve_task)
        return ip
