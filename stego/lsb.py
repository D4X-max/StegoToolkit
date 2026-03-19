import numpy as np
from PIL import Image
import os
from scipy.stats import chisquare

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



def analyze_anomaly_with_heatmap(image_path, heatmap_output_path):
    img = Image.open(image_path).convert("L")  # grayscale for simplicity
    pixels = np.array(img)

    # Extract LSB
    lsb = pixels & 1

    # --- 1. Global Ratio ---
    ones_ratio = np.mean(lsb)

    # --- 2. Local Block Analysis ---
    block_size = 8
    h, w = lsb.shape
    block_scores = []

    for i in range(0, h, block_size):
        for j in range(0, w, block_size):
            block = lsb[i:i+block_size, j:j+block_size]
            if block.size == 0:
                continue
            block_ratio = np.mean(block)
            block_scores.append(abs(block_ratio - 0.5))

    local_variation = np.mean(block_scores)

    # --- 3. Chi-Square Test ---
    hist, _ = np.histogram(pixels.flatten(), bins=256, range=(0,256))
    
    even = hist[::2]
    odd = hist[1::2]
    observed = even + odd
    expected = np.concatenate([observed/2, observed/2])

    chi_stat = np.sum(((hist - expected)**2) / (expected + 1e-6))

    # --- 4. Heatmap (variance-based) ---
    heatmap = np.abs(lsb - 0.5) * 255
    heatmap_img = Image.fromarray(heatmap.astype('uint8'))
    heatmap_img.save(heatmap_output_path)

    # --- Decision Logic ---
    suspicious_score = 0

    if 0.48 < ones_ratio < 0.52:
        suspicious_score += 1

    if local_variation < 0.05:  # too uniform
        suspicious_score += 1

    if chi_stat < 200:  # low chi-square = suspicious
        suspicious_score += 1

    if suspicious_score >= 2:
        status = "Suspicious"
        msg = f"Possible steganography detected (score={suspicious_score})"
    else:
        status = "Clean"
        msg = "No strong steganographic patterns detected"

    return {
        "status": status,
        "confidence": f"{suspicious_score}/3",
        "message": msg,
        "heatmap_url": f"/outputs/{os.path.basename(heatmap_output_path)}"
    }