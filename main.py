import sys
import multiprocessing
import argparse
from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow
from utils.logger import get_logger

logger = get_logger(__name__)

def main():
    logger.info("Initializing Network Intrusion Detection Platform...")
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--analyze', type=str, help='PCAP file to analyze offline')
    args, _ = parser.parse_known_args()
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = MainWindow(offline_mode=True) if args.analyze else MainWindow()
    if args.analyze:
        window.on_import(args.analyze)
        
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
