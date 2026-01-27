import os
import io
import zipfile
from flask import Flask, render_template, request, send_file, jsonify, send_from_directory
from crypto.aes import encrypt_data, decrypt_data
from stego.lsb import hide_lsb, extract_lsb, analyze_anomaly_with_heatmap, get_image_capacity
from pdf.pdf_crypto import hide_in_pdf, extract_from_pdf
from crypto.text_stego import hide_text_in_text, extract_text_from_text

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'

# Ensure directories exist
for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

@app.route('/')
def index():
    return render_template('index.html')

# --- IMAGE PROCESSING ---
@app.route('/process/image', methods=['POST'])
def process_image():
    mode = request.form.get('mode')
    password = request.form.get('password')
    file = request.files.get('file')
    
    if not file:
        return jsonify({"error": "No file provided"}), 400
    
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    output_filename = f"stego_{filename}"
    output_path = os.path.join(OUTPUT_FOLDER, output_filename)

    try:
        if mode == 'hide':
            text = request.form.get('text')
            if not text or not password:
                return jsonify({"error": "Text and Password required"}), 400
            
            encrypted = encrypt_data(text, password)
            hide_lsb(filepath, encrypted, output_path)
            
            if os.path.exists(filepath): os.remove(filepath)
            return send_file(output_path, as_attachment=True)
        
        elif mode == 'extract':
            if not password:
                return jsonify({"error": "Password required"}), 400
                
            extracted_enc = extract_lsb(filepath)
            if extracted_enc == "No hidden data found.":
                return jsonify({"result": extracted_enc})
                
            decrypted = decrypt_data(extracted_enc, password)
            if os.path.exists(filepath): os.remove(filepath)
            return jsonify({"result": decrypted})

    except Exception as e:
        if os.path.exists(filepath): os.remove(filepath)
        return jsonify({"error": str(e)}), 400

# --- ANOMALY DETECTION ---
@app.route('/process/detect', methods=['POST'])
def handle_detection():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, "detect_" + file.filename)
    file.save(filepath)
    
    heatmap_filename = "heatmap_" + file.filename + ".png"
    heatmap_path = os.path.join(OUTPUT_FOLDER, heatmap_filename)
    
    try:
        # Perform forensic analysis
        result = analyze_anomaly_with_heatmap(filepath, heatmap_path)
        
        # Cleanup original
        if os.path.exists(filepath): os.remove(filepath)
        
        # Result already contains status, confidence, and heatmap_url
        return jsonify(result)
    except Exception as e:
        if os.path.exists(filepath): os.remove(filepath)
        return jsonify({"error": str(e)}), 400

# --- CAPACITY CHECK ---
@app.route('/process/capacity', methods=['POST'])
def check_capacity():
    file = request.files.get('file')
    if not file: return jsonify({"error": "No file"}), 400
    
    filepath = os.path.join(UPLOAD_FOLDER, "temp_cap_" + file.filename)
    file.save(filepath)
    
    try:
        capacity = get_image_capacity(filepath)
        if os.path.exists(filepath): os.remove(filepath)
        return jsonify({"capacity": capacity})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- BATCH PROCESSING ---
@app.route('/process/batch', methods=['POST'])
def process_batch():
    password = request.form.get('password')
    text = request.form.get('text')
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({"error": "No files uploaded"}), 400

    memory_file = io.BytesIO()
    try:
        with zipfile.ZipFile(memory_file, 'w') as zf:
            for file in files:
                temp_in = os.path.join(UPLOAD_FOLDER, "batch_in_" + file.filename)
                file.save(temp_in)
                
                output_filename = f"hidden_{file.filename}.png"
                output_path = os.path.join(OUTPUT_FOLDER, output_filename)
                
                encrypted = encrypt_data(text, password)
                hide_lsb(temp_in, encrypted, output_path)
                
                zf.write(output_path, arcname=output_filename)
                
                # Cleanup
                if os.path.exists(temp_in): os.remove(temp_in)
                if os.path.exists(output_path): os.remove(output_path)
        
        memory_file.seek(0)
        return send_file(
            memory_file, 
            mimetype='application/zip',
            as_attachment=True, 
            download_name="batch_stego_assets.zip"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- PDF & TEXT UTILS ---
@app.route('/process/pdf', methods=['POST'])
def process_pdf():
    mode = request.form.get('mode')
    password = request.form.get('password')
    file = request.files['file']
    
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    output_path = os.path.join(OUTPUT_FOLDER, "secret_" + file.filename)

    try:
        if mode == 'hide':
            text = request.form.get('text')
            encrypted = encrypt_data(text, password)
            hide_in_pdf(filepath, encrypted, output_path)
            return send_file(output_path, as_attachment=True)
        elif mode == 'extract':
            extracted_enc = extract_from_pdf(filepath)
            decrypted = decrypt_data(extracted_enc, password)
            return jsonify({"result": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Serving static outputs (Heatmaps)
@app.route('/outputs/<path:filename>')
def custom_static(filename):
    return send_from_directory(OUTPUT_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000, use_reloader=False)