import os
import joblib
import numpy as np
from tqdm import tqdm  # The Progress Bar library
from sklearn.ensemble import RandomForestClassifier
from stego.lsb import hide_lsb, extract_forensic_features
from PIL import Image
import time

def generate_model():
    X, y = [], []
    train_dir = "training_data"
    
    if not os.path.exists(train_dir):
        print("\n[!] FATAL_ERROR: 'training_data' folder not found.")
        print("[*] Create the folder and add ~20 PNG images to begin.")
        return

    # Filter for PNG files only
    files = [f for f in os.listdir(train_dir) if f.endswith(".png")]
    
    if not files:
        print("\n[!] ERROR: No PNG images found in 'training_data'.")
        return

    print(f"\n[*] STARTING_STEGO_ML_TRAINING_SEQUENCE")
    print(f"[*] ANALYZING {len(files)} SOURCE ASSETS...\n")

    # The Progress Bar (desc is the text on the left)
    for filename in tqdm(files, desc="TRAINING_PROGRESS", unit="img", colour="blue"):
        path = os.path.join(train_dir, filename)
        
        try:
            # 1. Process Clean Image
            img_clean = Image.open(path).convert("L")
            feat_clean = extract_forensic_features(np.array(img_clean))
            X.append(feat_clean)
            y.append(0) # Label: Clean
            
            # 2. Create and Process Stego Image
            temp_stego = "temp_train.png"
            hide_lsb(path, "SECURE_PROTOCOL_TEST_123", temp_stego)
            
            img_stego = Image.open(temp_stego).convert("L")
            feat_stego = extract_forensic_features(np.array(img_stego))
            X.append(feat_stego)
            y.append(1) # Label: Stego
            
            if os.path.exists(temp_stego): os.remove(temp_stego)
            
            # Small sleep to make the bar visible (optional for demo)
            # time.sleep(0.1) 

        except Exception as e:
            print(f"\n[!] SKIP: {filename} (Corrupted or incompatible)")

    # 3. Fit Model
    print("\n[*] FITTING_RANDOM_FOREST_CLASSIFIER...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # 4. Save
    joblib.dump(model, 'stego_model.pkl')
    print("[*] SUCCESS: 'stego_model.pkl' synthesized.")
    print("[*] ANOMALY_DETECTION_ENGINE: READY.\n")

if __name__ == "__main__":
    generate_model()