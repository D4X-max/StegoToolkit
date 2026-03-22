import numpy as np
from PIL import Image
import os
from scipy.stats import chisquare
import joblib
from sklearn.ensemble import RandomForestClassifier

# --- CORE STEGANOGRAPHY ---

def hide_lsb(image_input, secret_data, output_path, bit_depth=1):
    """
    Hides secret_data in image using LSB steganography.
    
    Args:
        image_input: File path or BytesIO of the carrier image.
        secret_data: The string payload to hide (should already be encrypted).
        output_path:  Destination path or BytesIO buffer for the output PNG.
        bit_depth:    Number of LSBs per channel to use (1, 2, or 3).
                      Higher = more capacity, more detectable.
    """
    if bit_depth not in (1, 2, 3):
        raise ValueError("bit_depth must be 1, 2, or 3.")

    img = Image.open(image_input).convert('RGB')

    # Encode payload with delimiter, then to binary
    data        = secret_data + "#####"
    binary_secret = ''.join(format(ord(c), '08b') for c in data)
    total_bits  = len(binary_secret)

    pixels   = np.array(img)
    shape    = pixels.shape
    flat     = pixels.flatten().astype(np.int16)
    capacity = len(flat) * bit_depth

    if total_bits > capacity:
        raise ValueError(
            f"Payload too large for this image at {bit_depth}-bit depth. "
            f"Need {total_bits} bits, have {capacity} bits. "
            f"Try increasing bit depth or using a larger image."
        )

    # Build a bitmask for the chosen depth, e.g. depth=2 → mask=0b11111100
    mask = ~((1 << bit_depth) - 1) & 0xFF

    idx = 0
    for i in range(len(flat)):
        if idx >= total_bits:
            break
        # Grab the next `bit_depth` bits from the payload
        chunk = binary_secret[idx: idx + bit_depth]
        # Pad right if we're at the tail
        chunk = chunk.ljust(bit_depth, '0')
        chunk_val = int(chunk, 2)
        flat[i] = (int(flat[i]) & mask) | chunk_val
        idx += bit_depth

    final = np.clip(flat, 0, 255).astype('uint8').reshape(shape)
    Image.fromarray(final, 'RGB').save(output_path, format="PNG")


def extract_lsb(image_path, bit_depth=1):
    """
    Extracts a hidden payload from an LSB-encoded image.
    
    Args:
        image_path: File path or BytesIO of the stego image.
        bit_depth:  Must match the bit_depth used during hiding.
    """
    if bit_depth not in (1, 2, 3):
        raise ValueError("bit_depth must be 1, 2, or 3.")

    img    = Image.open(image_path).convert('RGB')
    flat   = np.array(img).flatten()
    mask   = (1 << bit_depth) - 1  # e.g. depth=2 → 0b11

    # Collect all bits
    bits = []
    for val in flat:
        chunk = format(int(val) & mask, f'0{bit_depth}b')
        bits.extend(list(chunk))

    binary_str  = ''.join(bits)
    all_bytes   = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]

    decoded = ""
    for byte in all_bytes:
        if len(byte) < 8:
            break
        decoded += chr(int(byte, 2))
        if decoded.endswith("#####"):
            return decoded[:-5]

    return "No hidden data found."


def get_image_capacity(image_path, bit_depth=1):
    """Returns the usable byte capacity for a given bit_depth."""
    with Image.open(image_path) as img:
        w, h = img.size
        total_bits = w * h * 3 * bit_depth
        # Subtract delimiter overhead (~40 bytes) and return bytes
        return max(0, (total_bits // 8) - 40)


# --- ML HELPER ---

def extract_forensic_features(pixels):
    """Converts image pixels into a numerical feature vector for the ML model."""
    lsb = pixels & 1

    # 1. Global LSB ratio
    ones_ratio = np.mean(lsb)

    # 2. Local variation across 8×8 blocks
    block_size   = 8
    h, w         = lsb.shape
    block_scores = []
    for i in range(0, h - block_size, block_size):
        for j in range(0, w - block_size, block_size):
            block = lsb[i:i+block_size, j:j+block_size]
            block_scores.append(abs(np.mean(block) - 0.5))
    local_variation = np.mean(block_scores) if block_scores else 0.5

    # 3. Chi-Square statistic over full pixel histogram
    hist, _  = np.histogram(pixels.flatten(), bins=256, range=(0, 256))
    observed = hist[::2] + hist[1::2]
    expected = np.concatenate([observed / 2, observed / 2])
    chi_stat = np.sum(((hist - expected) ** 2) / (expected + 1e-6))

    return np.array([ones_ratio, local_variation, chi_stat])


# --- ANOMALY DETECTION ---

def analyze_anomaly_with_heatmap(image_path, heatmap_output_path):
    """
    Classifies the image using a pre-trained Random Forest model,
    falling back to heuristic logic if the model file is missing.
    Also generates and saves an LSB-plane heatmap.
    """
    img    = Image.open(image_path).convert("L")
    pixels = np.array(img)

    # Save LSB plane as a visual heatmap
    lsb_plane   = (pixels & 1) * 255
    heatmap_img = Image.fromarray(lsb_plane.astype('uint8'))
    heatmap_img.save(heatmap_output_path)

    features   = extract_forensic_features(pixels).reshape(1, -1)
    model_path = 'stego_model.pkl'

    if os.path.exists(model_path):
        model       = joblib.load(model_path)
        prediction  = model.predict(features)[0]
        probability = model.predict_proba(features)[0][1]

        status     = "Suspicious" if probability > 0.55 else "Clean"
        confidence = f"{round(probability * 100, 1)}%"
        msg        = f"ML Engine: Statistical patterns suggest {status} intent."
    else:
        ones_ratio, local_var, chi = features[0]
        is_suspicious = (0.48 < ones_ratio < 0.52) and (local_var < 0.05)
        status        = "Suspicious" if is_suspicious else "Clean"
        confidence    = "Heuristic-Only"
        msg           = "Heuristic: LSB distribution is abnormally uniform."

    return {
        "status":      status,
        "confidence":  confidence,
        "message":     msg,
        "heatmap_url": f"/outputs/{os.path.basename(heatmap_output_path)}"
    }


# --- VISUAL DIFF TOOL ---

def generate_visual_diff(original_path, stego_path, diff_output_path, amplify=20):
    """
    Compares an original image against its stego version.
    Pixel differences are amplified so LSB changes become visible.

    Args:
        original_path:    Path to the original (clean) image.
        stego_path:       Path to the stego image.
        diff_output_path: Where to save the amplified diff PNG.
        amplify:          Multiplication factor for differences (default 20×).

    Returns:
        dict with diff stats and the output URL.
    """
    orig  = np.array(Image.open(original_path).convert('RGB')).astype(np.int16)
    stego = np.array(Image.open(stego_path).convert('RGB')).astype(np.int16)

    if orig.shape != stego.shape:
        raise ValueError(
            f"Image dimensions do not match: "
            f"original {orig.shape} vs stego {stego.shape}. "
            "Ensure both images are the same size."
        )

    diff = np.abs(orig - stego)

    # Stats before amplification
    changed_pixels = int(np.sum(np.any(diff > 0, axis=2)))
    total_pixels   = orig.shape[0] * orig.shape[1]
    max_diff       = int(diff.max())
    mean_diff      = round(float(diff.mean()), 4)

    # Amplify so 1-pixel LSB changes (value=1) become visible
    amplified = np.clip(diff * amplify, 0, 255).astype('uint8')
    Image.fromarray(amplified, 'RGB').save(diff_output_path, format="PNG")

    return {
        "changed_pixels": changed_pixels,
        "total_pixels":   total_pixels,
        "percent_changed": round((changed_pixels / total_pixels) * 100, 2),
        "max_diff":       max_diff,
        "mean_diff":      mean_diff,
        "diff_url":       f"/outputs/{os.path.basename(diff_output_path)}"
    }