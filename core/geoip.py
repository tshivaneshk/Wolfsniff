import time
import threading
import requests
import ipaddress
from utils.logger import get_logger

logger = get_logger(__name__)

class GeoIPManager:
    def __init__(self):
        self.cache = {}  # ip -> {"country": str, "isp": str}
        self.lock = threading.Lock()
        
    def _is_private(self, ip_str):
        try:
            return ipaddress.ip_address(ip_str).is_private
        except:
            return False

    def lookup(self, ip_str):
        if not ip_str or self._is_private(ip_str):
            return {"country": "Local Network", "isp": "Internal"}
            
        with self.lock:
            if ip_str in self.cache:
                return self.cache[ip_str]
                
        # To avoid blocking the main thread, if it's not in cache, we return a placeholder 
        # and spawn a thread to resolve it.
        threading.Thread(target=self._resolve, args=(ip_str,), daemon=True).start()
        return {"country": "Resolving...", "isp": "..."}
        
    def _resolve(self, ip_str):
        try:
            # We don't want to hit the API too fast
            time.sleep(0.5)
            response = requests.get(f"http://ip-api.com/json/{ip_str}?fields=country,isp", timeout=3)
            if response.status_code == 200:
                data = response.json()
                with self.lock:
                    self.cache[ip_str] = {
                        "country": data.get("country", "Unknown"),
                        "isp": data.get("isp", "Unknown")
                    }
            else:
                with self.lock:
                    self.cache[ip_str] = {"country": "Unknown", "isp": "Unknown"}
        except Exception as e:
            logger.debug(f"GeoIP resolution failed for {ip_str}: {e}")
            with self.lock:
                self.cache[ip_str] = {"country": "Unknown", "isp": "Unknown"}
