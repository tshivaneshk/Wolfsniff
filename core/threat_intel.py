import logging
import requests
import json
import os
from utils.config import BASE_DIR

class ThreatIntelManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config_path = os.path.join(BASE_DIR, "utils", "config.json")
        
    def query_ip(self, ip_address):
        api_keys = {}
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    api_keys = json.load(f)
            except Exception:
                pass
                
        abuse_key = api_keys.get("abuseipdb", "")
        if not abuse_key:
            return {'score': 0, 'reports': 0, 'domain': 'Unknown'}
            
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
            headers = {'Accept': 'application/json', 'Key': abuse_key}
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=2)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'score': data.get('abuseConfidenceScore', 0),
                    'reports': data.get('totalReports', 0),
                    'domain': data.get('domain', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'usageType': data.get('usageType', 'Unknown'),
                    'country': data.get('countryName', 'Unknown'),
                    'city': data.get('city', 'Unknown')
                }
        except Exception as e:
            self.logger.error(f"Threat Intel API Error: {e}")
            
        return {'score': 0, 'reports': 0, 'domain': 'Unknown'}
        
    def map_cve(self, payload):
        pass
