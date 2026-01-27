# 🛡️ StegoToolkit: Advanced Applied Cryptography Suite

**StegoToolkit** is a high-performance security application designed for hiding and detecting encrypted data within digital media. Utilizing **AES-256-CBC** encryption and **NumPy-optimized vectorized LSB** (Least Significant Bit) injection, it offers a robust platform for secure communication and forensic image analysis.



## ✨ Key Features

* **Image Steganography:** Hide encrypted text inside PNG/BMP files using bit-plane manipulation.
* **AES-256 Security:** All payloads are encrypted using industry-standard AES-256-CBC with PKCS7 padding and PBKDF2 key derivation.
* **Forensic Anomaly Scanner:** A heuristic model that generates **Bit-Plane Heatmaps** to detect hidden data in suspicious images.
* **PDF Metadata Vault:** Inject secret strings into PDF document metadata fields.
* **Batch Processing:** Securely encode multiple images simultaneously and download them as a ZIP archive.
* **Real-time Capacity Analysis:** Dynamically calculates the available storage space in an image to prevent visual corruption.

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have **Python 3.10+** installed on your system.

### 2. Installation
Clone the repository and install the required dependencies using the requirements file:

```bash
# Clone the repository
git clone [https://github.com/yourusername/stego-toolkit.git](https://github.com/yourusername/stego-toolkit.git)
cd stego-toolkit

# Install dependencies
pip install -r requirements.txt
```

### Launching the application
```bash
python app.py
```
Navigate to the web address http://127.0.0.1:5000
