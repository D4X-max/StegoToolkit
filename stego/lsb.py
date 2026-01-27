import numpy as np
from PIL import Image
import os

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
    """
    Original stable detection: 
    Visualizes the LSB plane to reveal patterns and checks global LSB density.
    """
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)
    
    # Create a visual Bit-Plane (LSB * 255 to make it visible)
    lsb_plane = (pixels & 1) * 255
    
    # Calculate global density
    lsb_flat = pixels.flatten() & 1
    ones_ratio = np.mean(lsb_flat)
    
    # Standard threshold logic
    is_suspicious = 0.47 < ones_ratio < 0.53
    
    # Save the LSB visualization
    heatmap_img = Image.fromarray(lsb_plane.astype('uint8'), 'RGB')
    heatmap_img.save(heatmap_output_path)

    if is_suspicious:
        status, msg = "Suspicious", f"LSB distribution is abnormally uniform ({ones_ratio:.4f})."
    else:
        status, msg = "Clean", "LSB distribution matches natural noise."

    return {
        "status": status,
        "confidence": "N/A",
        "message": msg,
        "heatmap_url": f"/outputs/{os.path.basename(heatmap_output_path)}"
    }