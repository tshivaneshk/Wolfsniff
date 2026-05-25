import re
from utils.logger import get_logger

logger = get_logger(__name__)

class RuleEngine:
    def __init__(self):
        self.rules = []
        
    def load_rules(self, file_path):
        count = 0
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    
                    # Basic parser: alert tcp any any -> any any (msg:"Test"; sid:1;)
                    match = re.match(r'alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*)\)', line, re.IGNORECASE)
                    if match:
                        proto, src_ip, src_port, dst_ip, dst_port, opts_str = match.groups()
                        
                        opts = {}
                        for opt_match in re.finditer(r'(\w+)\s*:\s*([^;]+);', opts_str):
                            key, val = opt_match.groups()
                            opts[key.strip()] = val.strip().strip('"')
                            
                        self.rules.append({
                            'proto': proto.lower(),
                            'src_ip': src_ip, 'src_port': src_port,
                            'dst_ip': dst_ip, 'dst_port': dst_port,
                            'opts': opts,
                            'raw': line
                        })
                        count += 1
            logger.info(f"Loaded {count} signature rules from {file_path}")
            return count
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return -1

    def match_flow(self, flow_data):
        for rule in self.rules:
            if rule['proto'] != 'any' and rule['proto'] != flow_data.get('protocol', '').lower():
                continue
                
            if rule['src_ip'] != 'any' and rule['src_ip'] != flow_data.get('src_ip'): continue
            if rule['dst_ip'] != 'any' and rule['dst_ip'] != flow_data.get('dst_ip'): continue
            if rule['src_port'] != 'any' and str(rule['src_port']) != str(flow_data.get('src_port')): continue
            if rule['dst_port'] != 'any' and str(rule['dst_port']) != str(flow_data.get('dst_port')): continue
            
            return rule['opts'].get('msg', 'Signature Match')
            
        return None
