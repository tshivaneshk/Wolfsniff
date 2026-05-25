import os
import sys

if getattr(sys, 'frozen', False):
    # PyInstaller temporary folder (onefile) OR installation directory (onedir)
    RESOURCE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    # Industry Standard: Store writable databases and logs in %LOCALAPPDATA%
    app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
    DATA_DIR = os.path.join(app_data, 'Wolfsniff')
else:
    RESOURCE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = RESOURCE_DIR

BASE_DIR = RESOURCE_DIR

# Database (Persistent)
DB_DIR = os.path.join(DATA_DIR, 'database')
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, 'ids_events.db')

# ML Models (Read-Only Resources)
MODEL_DIR = os.path.join(RESOURCE_DIR, 'ml')
MODEL_PATH = os.path.join(MODEL_DIR, 'rf_model.joblib')
ENCODERS_PATH = os.path.join(MODEL_DIR, 'encoders.joblib')
THRESHOLDS_PATH = os.path.join(MODEL_DIR, 'thresholds.json')

# Flow settings
FLOW_TIMEOUT_SEC = 30
MAX_FLOWS_IN_MEMORY = 10000

# Feature columns corresponding exactly to the UNSW-NB15 schema (minus id, attack_cat, label)
UNSW_NB15_COLUMNS = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 
    'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 
    'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len', 
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

# Supported risk policies
POLICIES = {
    'balanced': 'balanced',
    'strict': 'strict',
    'conservative': 'conservative'
}
