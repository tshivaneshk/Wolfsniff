import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import roc_curve, precision_recall_curve
from imblearn.over_sampling import SMOTE
from utils.config import BASE_DIR, MODEL_PATH, ENCODERS_PATH, THRESHOLDS_PATH, UNSW_NB15_COLUMNS
from utils.logger import get_logger

logger = get_logger(__name__)

def generate_synthetic_data(num_samples=1000):
    """Generates synthetic UNSW-NB15 data for offline fallback."""
    logger.info("Generating synthetic fallback dataset...")
    
    np.random.seed(42)
    data = {}
    
    # Generate numerical features (dummy data)
    for col in UNSW_NB15_COLUMNS:
        if col not in ['proto', 'service', 'state']:
            data[col] = np.random.rand(num_samples) * 100
            
    # Generate categorical features
    data['proto'] = np.random.choice(['tcp', 'udp', 'icmp', 'arp', 'unknown'], num_samples)
    data['service'] = np.random.choice(['http', 'dns', 'ftp', 'ssh', 'smtp', 'unknown'], num_samples)
    data['state'] = np.random.choice(['CON', 'INT', 'FIN', 'REQ', 'RST'], num_samples)
    
    df = pd.DataFrame(data)
    
    # Add label (0 normal, 1 attack)
    df['label'] = np.random.choice([0, 1], num_samples, p=[0.7, 0.3])
    
    # Split into train/test
    train = df.iloc[:int(num_samples*0.8)].copy()
    test = df.iloc[int(num_samples*0.8):].copy()
    
    return train, test

def load_or_generate_data():
    dataset_dir = os.path.join(BASE_DIR, 'dataset')
    train_path = os.path.join(dataset_dir, 'UNSW_NB15_training-set.csv')
    test_path = os.path.join(dataset_dir, 'UNSW_NB15_testing-set.csv')
    
    if os.path.exists(train_path) and os.path.exists(test_path):
        logger.info(f"Loading real datasets from {dataset_dir}")
        train = pd.read_csv(train_path)
        test = pd.read_csv(test_path)
        # Drop 'id' and 'attack_cat' if they exist
        for df in [train, test]:
            if 'id' in df.columns:
                df.drop(columns=['id'], inplace=True)
            if 'attack_cat' in df.columns:
                df.drop(columns=['attack_cat'], inplace=True)
    else:
        logger.warning(f"Datasets not found in {dataset_dir}. Falling back to synthetic data.")
        train, test = generate_synthetic_data()
        
    return train, test

def train_and_save():
    train, test = load_or_generate_data()
    
    full_data = pd.concat([train, test], axis=0)
    
    # Ensure column order matches UNSW_NB15_COLUMNS
    cols = [col for col in UNSW_NB15_COLUMNS if col in full_data.columns]
    
    # Preprocessing
    encoders = {}
    for col in ['proto', 'service', 'state']:
        if col in full_data.columns:
            full_data[col] = full_data[col].astype(str).replace(['-', 'nan', 'None'], 'unknown')
            le = LabelEncoder()
            full_data[col] = le.fit_transform(full_data[col])
            encoders[col] = le
            
    train_clean = full_data.iloc[:len(train), :].copy()
    test_clean = full_data.iloc[len(train):, :].copy()
    
    # Select features based on UNSW_NB15_COLUMNS configuration
    feature_cols = [c for c in UNSW_NB15_COLUMNS if c in train_clean.columns]
    
    X_train = train_clean[feature_cols]
    y_train = train_clean['label']
    
    X_test = test_clean[feature_cols]
    y_test = test_clean['label']
    
    # SMOTE
    logger.info("Applying SMOTE...")
    try:
        # Check if we have enough samples in minority class
        k_neighbors = min(3, len(y_train[y_train==1])-1)
        if k_neighbors > 0:
            sm = SMOTE(random_state=42, k_neighbors=k_neighbors)
            X_train_bal, y_train_bal = sm.fit_resample(X_train, y_train)
        else:
            X_train_bal, y_train_bal = X_train, y_train
    except Exception as e:
        logger.warning(f"SMOTE failed: {e}. Proceeding without SMOTE.")
        X_train_bal, y_train_bal = X_train, y_train
        
    # Train Random Forest
    logger.info("Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_split=5, 
        min_samples_leaf=2, random_state=42, n_jobs=-1
    )
    rf_model.fit(X_train_bal, y_train_bal)
    
    # Calculate thresholds
    logger.info("Calculating risk thresholds...")
    attack_prob = rf_model.predict_proba(X_test)[:, 1]
    
    # ROC Curve for balanced
    fpr, tpr, roc_thresholds = roc_curve(y_test, attack_prob)
    youden_index = tpr - fpr
    balanced_idx = np.argmax(youden_index)
    balanced_threshold = float(roc_thresholds[balanced_idx])
    
    # Precision-Recall for strict
    precision, recall, pr_thresholds = precision_recall_curve(y_test, attack_prob)
    target_recall = 0.98
    valid_indices = np.where(recall >= target_recall)[0]
    strict_threshold = float(pr_thresholds[valid_indices[-1]]) if len(valid_indices) > 0 else balanced_threshold
    
    # Percentile for conservative
    conservative_threshold = float(np.percentile(attack_prob, 90))
    
    thresholds = {
        'balanced': balanced_threshold,
        'strict': strict_threshold,
        'conservative': conservative_threshold
    }
    
    # Save models and thresholds
    logger.info("Saving model, encoders, and thresholds...")
    joblib.dump(rf_model, MODEL_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    with open(THRESHOLDS_PATH, 'w') as f:
        json.dump(thresholds, f)
        
    logger.info("Training complete!")

if __name__ == '__main__':
    train_and_save()
