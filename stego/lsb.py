import numpy as np
from PIL import Image
import os
from scipy.stats import chisquare
import joblib # for ML model loading
from sklearn.ensemble import RandomForestClassifier

# --- CORE STEGANOGRAPHY ---

def hide_lsb(image_input, secret_data, output_path):
    # Load image and convert to RGB
    img = Image.open(image_input).convert('RGB')
    
    # Prepare binary data with the original delimiter
    data = secret_data + "#####"
    binary_secret = ''.join([format(ord(i), '08b') for i in data])
    
    # Convert image to a numpy array
    pixels = np.array(img)
    shape = pixels.shape
    
    # Flatten to 1D and convert to int16 to avoid uint8 overflow
    flat_pixels = pixels.flatten().astype(np.int16) 
    
    if len(binary_secret) > len(flat_pixels):
        raise ValueError("Data too large for image size.")

    # Perform bit replacement (The reliable loop)
    for i in range(len(binary_secret)):
        # Clear the LSB (& ~1) and set the new bit
        flat_pixels[i] = (int(flat_pixels[i]) & ~1) | int(binary_secret[i])
        
    # Clip values to 0-255 range and cast back to uint8
    final_pixels = np.clip(flat_pixels, 0, 255).astype('uint8')
    
    # Reshape to original image dimensions
    new_pixels = final_pixels.reshape(shape)
    new_img = Image.fromarray(new_pixels, 'RGB')
    
    # Save as PNG (Lossless)
    new_img.save(output_path, format="PNG")

def extract_lsb(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img).flatten()
    
    # Extract LSBs one by one
    binary_data = "".join([str(pixels[i] & 1) for i in range(len(pixels))])
    
    # Break into 8-bit bytes
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    
    decoded_data = ""
    for byte in all_bytes:
        if len(byte) < 8: break
        decoded_data += chr(int(byte, 2))
        
        # Check for original delimiter
        if decoded_data.endswith("#####"):
            return decoded_data[:-5]
            
    return "No hidden data found."

def get_image_capacity(image_path):
    with Image.open(image_path) as img:
        width, height = img.size
        # Total bits = pixels * 3 channels / 8 bits per byte
        total_capacity_bytes = (width * height * 3) // 8
        return max(0, total_capacity_bytes - 40)

# --- FORENSIC ANALYSIS (First Stable Version) ---



# --- ML HELPER ---
def extract_forensic_features(pixels):
    """Converts image pixels into a numerical feature vector for the ML model."""
    lsb = pixels & 1
    
    # 1. Global Ratio
    ones_ratio = np.mean(lsb)
    
    # 2. Local Variation (8x8 blocks)
    block_size = 8
    h, w = lsb.shape
    block_scores = []
    for i in range(0, h - block_size, block_size):
        for j in range(0, w - block_size, block_size):
            block = lsb[i:i+block_size, j:j+block_size]
            block_scores.append(abs(np.mean(block) - 0.5))
    local_variation = np.mean(block_scores) if block_scores else 0.5
    
    # 3. Chi-Square Statistic
    hist, _ = np.histogram(pixels.flatten(), bins=256, range=(0,256))
    observed = hist[::2] + hist[1::2]
    expected = np.concatenate([observed/2, observed/2])
    chi_stat = np.sum(((hist - expected)**2) / (expected + 1e-6))
    
    return np.array([ones_ratio, local_variation, chi_stat])

# --- UPDATED ANALYZE FUNCTION ---
def analyze_anomaly_with_heatmap(image_path, heatmap_output_path):
    """
    Uses a pre-trained Random Forest model to classify the image.
    Falls back to heuristic logic if model is missing.
    """
    img = Image.open(image_path).convert("L")
    pixels = np.array(img)
    
    # Generate the visual heatmap (keep this for the UI)
    lsb_plane = (pixels & 1) * 255
    heatmap_img = Image.fromarray(lsb_plane.astype('uint8'))
    heatmap_img.save(heatmap_output_path)
    
    # Extract features for the model
    features = extract_forensic_features(pixels).reshape(1, -1)
    
    model_path = 'stego_model.pkl'
    
    if os.path.exists(model_path):
        # --- ML PATH ---
        model = joblib.load(model_path)
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0][1] 
        
        status = "Suspicious" if probability > 0.55 else "Clean"
        confidence = f"{round(probability * 100, 1)}%"
        msg = f"ML Engine: Statistical patterns suggest {status} intent."
    else:
        # --- BACKUP: HEURISTIC PATH (If you haven't trained yet) ---
        ones_ratio, local_var, chi = features[0]
        is_suspicious = (0.48 < ones_ratio < 0.52) and (local_var < 0.05)
        status = "Suspicious" if is_suspicious else "Clean"
        confidence = "Heuristic-Only"
        msg = "Heuristic: LSB distribution is abnormally uniform."

    return {
        "status": status,
        "confidence": confidence,
        "message": msg,
        "heatmap_url": f"/outputs/{os.path.basename(heatmap_output_path)}"
    }