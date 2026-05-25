import os
import json
import joblib
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from utils.config import MODEL_PATH, ENCODERS_PATH, THRESHOLDS_PATH, UNSW_NB15_COLUMNS
from utils.logger import get_logger

logger = get_logger(__name__)

class ModelManager:
    def __init__(self):
        self.model = None
        self.encoders = {}
        self.thresholds = {
            'balanced': 0.5,
            'strict': 0.5,
            'conservative': 0.5
        }
        self.load_models()

    def load_models(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH):
                self.model = joblib.load(MODEL_PATH)
                self.encoders = joblib.load(ENCODERS_PATH)
                if os.path.exists(THRESHOLDS_PATH):
                    with open(THRESHOLDS_PATH, 'r') as f:
                        self.thresholds = json.load(f)
                logger.info("Successfully loaded ML model, encoders, and thresholds.")
            else:
                logger.warning("ML models not found. Please run ml/train_model.py first.")
        except Exception as e:
            logger.error(f"Error loading models: {e}")

    def evaluate_flow(self, flow_features_dict, policy="balanced"):
        if not self.model:
            return 0.0, "LOW", "Allow", "Model not loaded", ["Missing ML Engine"], [], ["Check system ML dependencies"]

        try:
            # 1. Map dict to DataFrame in the exact feature order
            row = []
            for col in UNSW_NB15_COLUMNS:
                val = flow_features_dict.get(col, 0)
                if col in ['proto', 'service', 'state']:
                    val = str(val).lower() if val else 'unknown'
                else:
                    val = float(val) if val is not None else 0.0
                row.append(val)
                
            df = pd.DataFrame([row], columns=UNSW_NB15_COLUMNS)
            
            # 2. Apply Encoders securely
            for col in ['proto', 'service', 'state']:
                if col in self.encoders:
                    classes = self.encoders[col].classes_
                    val = df[col].iloc[0]
                    if val not in classes:
                        val = 'unknown' if 'unknown' in classes else classes[0]
                    df[col] = self.encoders[col].transform([val])[0]

            # 3. Predict Probability
            prob = float(self.model.predict_proba(df)[0][1])

            # 4. Adaptive Security Policy based on user's architecture
            policy = policy.lower()
            target_threshold = self.thresholds.get(policy, self.thresholds.get('balanced', 0.806))
            
            # MEDIUM is defined as "Probability ≈ Threshold" (within 20% margin)
            medium_threshold = target_threshold * 0.80
            
            if prob >= target_threshold:
                severity = "HIGH"
                action = "Restrict"
            elif prob >= medium_threshold:
                severity = "MEDIUM"
                action = "Monitor"
            else:
                severity = "LOW"
                action = "Allow"

            # 5. Explainable AI: Rule-based heuristic reasons
            explanation, reasons, activities, recommendations = self._generate_explanation(flow_features_dict, prob, severity)

            return prob, severity, action, explanation, reasons, activities, recommendations
            
        except Exception as e:
            logger.error(f"Error evaluating flow: {e}")
            return 0.0, "LOW", "Allow", f"Error evaluating flow: {e}", [], [], []

    def _generate_explanation(self, features, prob, severity):
        if severity == "LOW":
            return "Normal baseline traffic.", ["Baseline metrics normal"], ["Normal Network Traffic"], ["No action required"]
            
        reasons = []
        activities = []
        actions = []
        
        if features.get('rate', 0) > 200:
            reasons.append(f"High packet rate ({features.get('rate'):.1f} pkt/s)")
            activities.append("Network Denial of Service (DoS) [MITRE T1498]")
            actions.append("Rate-limit source IP at Edge Firewall")
            
        if features.get('sload', 0) > 1000000:
            reasons.append(f"Abnormally high outbound traffic ({features.get('sload')/1e6:.2f} Mb/s)")
            activities.append("Data Exfiltration [MITRE T1041]")
            actions.append("Inspect host for unauthorized file transfers")
            
        if features.get('ct_dst_sport_ltm', 0) > 5 or features.get('ct_src_dport_ltm', 0) > 5:
            reasons.append("Frequent connection sweeps")
            activities.append("Port Scanning / Discovery [MITRE T1046]")
            actions.append("Block source IP; Investigate target ports")
            
        if features.get('sloss', 0) > 5 or features.get('dloss', 0) > 5:
            reasons.append("High packet loss or retransmission")
            activities.append("Connection Tampering / Evasion [MITRE T1562]")
            actions.append("Monitor for C2 beacons")
            
        if features.get('tcprtt', 0) > 0.5:
            reasons.append(f"Excessive TCP handshake latency ({features.get('tcprtt'):.3f}s)")
            activities.append("Slowloris / Stealth Scan")
            actions.append("Enable SYN flood protection")
            
        if features.get('ct_dst_src_ltm', 0) > 10:
            reasons.append("Frequent repeated connections")
            activities.append("Brute-Force Behavior / Tool Transfer [MITRE T1105]")
            actions.append("Isolate suspicious host temporarily")
            
        if not reasons:
            reasons.append("Anomalous combination of statistical flow metrics")
            activities.append("Unknown Suspicious Behavior")
            actions.append("Review PCAP file manually")
            
        explanation = "; ".join(reasons)
        # return unique lists while preserving some order
        return explanation, list(dict.fromkeys(reasons)), list(dict.fromkeys(activities)), list(dict.fromkeys(actions))
