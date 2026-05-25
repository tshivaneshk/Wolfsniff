import csv
import os
import datetime
from database.db_manager import DatabaseManager

class ReportGenerator:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def generate_pdf_report(self, filepath):
        # We rename the method to keep compatibility with existing calls, but generate CSV
        with self.db.lock:
            conn = self.db._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100')
            rows = cursor.fetchall()
            col_names = [description[0] for description in cursor.description]
            conn.close()

        csv_path = filepath
        if not csv_path.endswith('.csv'):
            csv_path = csv_path.replace('.pdf', '.csv')
            
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Wolfsniff - Threat Report", f"Generated: {datetime.datetime.now()}"])
            writer.writerow([])
            writer.writerow(col_names)
            for row in rows:
                writer.writerow(row)
        return csv_path
