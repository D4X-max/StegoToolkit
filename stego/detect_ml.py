import numpy as np
from PIL import Image
import os
import joblib # for saving the model
from sklearn.ensemble import RandomForestClassifier

def extract_features(image_path):
    img = Image.open(image_path).convert("L")
    pixels = np.array(img)
    lsb = pixels & 1
    
    # Feature 1: Global Ratio (Entropy)
    ones_ratio = np.mean(lsb)
    
    # Feature 2: Local Variation (Blockiness)
    block_size = 8
    h, w = lsb.shape
    block_scores = []
    for i in range(0, h - block_size, block_size):
        for j in range(0, w - block_size, block_size):
            block = lsb[i:i+block_size, j:j+block_size]
            block_scores.append(abs(np.mean(block) - 0.5))
    local_var = np.mean(block_scores)
    
    # Feature 3: Chi-Square Stat
    hist, _ = np.histogram(pixels.flatten(), bins=256, range=(0,256))
    observed = hist[::2] + hist[1::2]
    expected = np.concatenate([observed/2, observed/2])
    chi_stat = np.sum(((hist - expected)**2) / (expected + 1e-6))
    
    # Return as a 1D array for the ML model
    return np.array([ones_ratio, local_var, chi_stat])

# --- TRAINING (Run once to create 'stego_model.pkl') ---
def train_simple_model():
    # Example training data: [Ratio, LocalVar, Chi]
    # In a real scenario, you'd loop through 100 clean and 100 stego images
    X = np.array([
        [0.50, 0.02, 150], # Typical Stego
        [0.45, 0.12, 800], # Typical Clean
        [0.51, 0.01, 120], # Typical Stego
        [0.42, 0.15, 950]  # Typical Clean
    ])
    y = np.array([1, 0, 1, 0]) # 1 = Stego, 0 = Clean
    
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, y)
    joblib.dump(model, 'stego_model.pkl')

# --- UPDATED DETECTION FUNCTION ---
def analyze_anomaly_ml(image_path, heatmap_output_path):
    features = extract_features(image_path).reshape(1, -1)
    
    # Load your trained model
    if not os.path.exists('stego_model.pkl'):
        train_simple_model()
    
    model = joblib.load('stego_model.pkl')
    
    # Predict
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0][1] # Probability of being Stego
    
    # Generate Heatmap (Keep your original visual logic)
    img = Image.open(image_path).convert("L")
    lsb = np.array(img) & 1
    heatmap = np.abs(lsb - 0.5) * 255
    Image.fromarray(heatmap.astype('uint8')).save(heatmap_output_path)
    
    status = "Suspicious" if probability > 0.6 else "Clean"
    
    return {
        "status": status,
        "confidence": f"{round(probability * 100, 2)}%",
        "message": f"ML Analysis: {status} pattern detected with high entropy.",
        "heatmap_url": f"/outputs/{os.path.basename(heatmap_output_path)}"
    }