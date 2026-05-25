import sqlite3
import threading
from utils.config import DB_PATH
from utils.logger import get_logger

logger = get_logger(__name__)

class DatabaseManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.lock:
            cursor = self.conn.cursor()
            
            # Create flows table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    duration REAL,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    packets_sent INTEGER,
                    packets_received INTEGER,
                    threat_score REAL,
                    severity TEXT
                )
            ''')
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    threat_score REAL,
                    severity TEXT,
                    explanation TEXT,
                    FOREIGN KEY(flow_id) REFERENCES flows(id)
                )
            ''')
            
            # Create system logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    level TEXT,
                    message TEXT
                )
            ''')
            
            try:
                cursor.execute('ALTER TABLE alerts ADD COLUMN threat_intel TEXT')
                self.conn.commit()
            except sqlite3.OperationalError:
                pass # Column already exists
            
            self.conn.commit()

    def insert_flow(self, flow_data):
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO flows (
                        src_ip, dst_ip, src_port, dst_port, protocol,
                        duration, bytes_sent, bytes_received, packets_sent, packets_received,
                        threat_score, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    flow_data.get('src_ip', ''), flow_data.get('dst_ip', ''),
                    flow_data.get('src_port', 0), flow_data.get('dst_port', 0),
                    flow_data.get('protocol', ''), flow_data.get('dur', 0.0),
                    flow_data.get('sbytes', 0), flow_data.get('dbytes', 0),
                    flow_data.get('spkts', 0), flow_data.get('dpkts', 0),
                    flow_data.get('threat_score', 0.0), flow_data.get('severity', 'LOW')
                ))
                flow_id = cursor.lastrowid
                self.conn.commit()
                return flow_id
            except Exception as e:
                logger.error(f"Error inserting flow: {e}")
                return None

    def insert_alert(self, alert_data):
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (
                        flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                        threat_score, severity, explanation, threat_intel
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_data.get('flow_id'), alert_data.get('src_ip'),
                    alert_data.get('dst_ip'), alert_data.get('src_port'),
                    alert_data.get('dst_port'), alert_data.get('protocol'),
                    alert_data.get('threat_score'), alert_data.get('severity'),
                    alert_data.get('explanation'), alert_data.get('threat_intel')
                ))
                self.conn.commit()
            except Exception as e:
                logger.error(f"Error inserting alert: {e}")

    def update_live_alert(self, src_ip, dst_ip, src_port, dst_port, protocol, real_flow_id, threat_intel):
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    UPDATE alerts
                    SET flow_id = ?, threat_intel = ?
                    WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ? AND protocol = ?
                    AND CAST(flow_id AS TEXT) LIKE 'live_%'
                ''', (real_flow_id, threat_intel, src_ip, dst_ip, src_port, dst_port, protocol))
                self.conn.commit()
            except Exception as e:
                logger.error(f"Error updating live alert: {e}")

    def get_recent_alerts(self, limit=100):
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                
                # Format to list of dicts
                keys = ['id', 'flow_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'threat_score', 'severity', 'explanation']
                return [dict(zip(keys, row)) for row in rows]
            except Exception as e:
                logger.error(f"Error getting alerts: {e}")
                return []

    def clear_all(self):
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM flows')
                cursor.execute('DELETE FROM alerts')
                self.conn.commit()
                self.conn.isolation_level = None
                self.conn.execute('VACUUM')
                self.conn.isolation_level = ''
            except Exception as e:
                logger.error(f"Error clearing db: {e}")

    def get_stats(self):
        with self.lock:
            try:
                cursor = self.conn.cursor()
                stats = {}
                # Protocol distribution
                cursor.execute('SELECT protocol, COUNT(*) FROM flows GROUP BY protocol')
                stats['protocols'] = dict(cursor.fetchall())
                
                # Severity distribution
                cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
                stats['severities'] = dict(cursor.fetchall())
                
                # Total flows
                cursor.execute('SELECT COUNT(*) FROM flows')
                row = cursor.fetchone()
                stats['total_flows'] = row[0] if row else 0
                
                # Unique Source IPs
                cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM flows')
                row = cursor.fetchone()
                stats['unique_src'] = row[0] if row else 0
                
                # Unique Target IPs
                cursor.execute('SELECT COUNT(DISTINCT dst_ip) FROM flows')
                row = cursor.fetchone()
                stats['unique_dst'] = row[0] if row else 0
                
                # Top Targeted Ports
                cursor.execute('SELECT dst_port, COUNT(*) FROM flows GROUP BY dst_port ORDER BY COUNT(*) DESC LIMIT 5')
                stats['top_ports'] = cursor.fetchall()
                
                # Total alerts
                cursor.execute('SELECT COUNT(*) FROM alerts')
                row = cursor.fetchone()
                stats['total_alerts'] = row[0] if row else 0
                
                return stats
            except Exception as e:
                logger.error(f"Error getting stats: {e}")
                return {}
    
    def __del__(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
