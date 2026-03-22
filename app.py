import os
import io
import zipfile
import base64
from io import BytesIO
from PIL import Image
from flask import Flask, render_template, request, send_file, jsonify, send_from_directory
from aes import encrypt_data, decrypt_data
from stego.lsb import hide_lsb, extract_lsb, analyze_anomaly_with_heatmap, get_image_capacity, generate_visual_diff
from pdf.pdf_crypto import hide_in_pdf, extract_from_pdf
from text_stego import hide_text_in_text, extract_text_from_text
from flask_socketio import SocketIO, emit

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
socketio = SocketIO(app, cors_allowed_origins="*")
CARRIER_PATH = "static/favicon.ico.png"

for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# ─── HELPERS ────────────────────────────────────────────────────────────────

def safe_remove(*paths):
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except OSError:
            pass

def error_response(message, code=400):
    """Standardised JSON error envelope."""
    return jsonify({"error": message}), code

# ─── NAVIGATION ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/local')
def local_toolkit():
    return render_template('local.html')

@app.route('/live')
def live_chat():
    return render_template('live.html')

# ─── IMAGE STEGANOGRAPHY ─────────────────────────────────────────────────────

@app.route('/process/image', methods=['POST'])
def process_image():
    mode      = request.form.get('mode')
    password  = request.form.get('password', '').strip()
    file      = request.files.get('file')
    bit_depth = int(request.form.get('bit_depth', 1))

    if not file or file.filename == '':
        return error_response("No file provided.")
    if not password:
        return error_response("A passphrase is required.")
    if bit_depth not in (1, 2, 3):
        return error_response("bit_depth must be 1, 2, or 3.")

    filepath        = os.path.join(UPLOAD_FOLDER, file.filename)
    output_filename = f"stego_{file.filename}"
    output_path     = os.path.join(OUTPUT_FOLDER, output_filename)
    file.save(filepath)

    try:
        if mode == 'hide':
            text = request.form.get('text', '').strip()
            if not text:
                return error_response("Payload text is required for encoding.")

            encrypted = encrypt_data(text, password)
            hide_lsb(filepath, encrypted, output_path, bit_depth=bit_depth)
            safe_remove(filepath)
            return send_file(output_path, as_attachment=True)

        elif mode == 'extract':
            extracted_enc = extract_lsb(filepath, bit_depth=bit_depth)
            safe_remove(filepath)

            if extracted_enc == "No hidden data found.":
                return jsonify({"result": extracted_enc})

            decrypted = decrypt_data(extracted_enc, password)
            return jsonify({"result": decrypted})

        else:
            safe_remove(filepath)
            return error_response(f"Unknown mode '{mode}'. Use 'hide' or 'extract'.")

    except ValueError as e:
        safe_remove(filepath, output_path)
        return error_response(str(e))
    except Exception as e:
        safe_remove(filepath, output_path)
        return error_response(f"Unexpected error: {str(e)}", 500)

# ─── ANOMALY DETECTION ───────────────────────────────────────────────────────

@app.route('/process/detect', methods=['POST'])
def handle_detection():
    file = request.files.get('file')
    if not file or file.filename == '':
        return error_response("No file uploaded.")

    filepath         = os.path.join(UPLOAD_FOLDER, "detect_" + file.filename)
    heatmap_filename = "heatmap_" + file.filename + ".png"
    heatmap_path     = os.path.join(OUTPUT_FOLDER, heatmap_filename)
    file.save(filepath)

    try:
        result = analyze_anomaly_with_heatmap(filepath, heatmap_path)
        safe_remove(filepath)
        return jsonify(result)
    except Exception as e:
        safe_remove(filepath)
        return error_response(f"Detection failed: {str(e)}", 500)

# ─── CAPACITY CHECK ──────────────────────────────────────────────────────────

@app.route('/process/capacity', methods=['POST'])
def check_capacity():
    file      = request.files.get('file')
    bit_depth = int(request.form.get('bit_depth', 1))

    if not file:
        return error_response("No file provided.")

    filepath = os.path.join(UPLOAD_FOLDER, "temp_cap_" + file.filename)
    file.save(filepath)

    try:
        capacity = get_image_capacity(filepath, bit_depth=bit_depth)
        safe_remove(filepath)
        return jsonify({"capacity": capacity})
    except Exception as e:
        safe_remove(filepath)
        return error_response(str(e), 500)

# ─── VISUAL DIFF ─────────────────────────────────────────────────────────────

@app.route('/process/diff', methods=['POST'])
def visual_diff():
    original = request.files.get('original')
    stego    = request.files.get('stego')

    if not original or not stego:
        return error_response("Both 'original' and 'stego' image files are required.")

    orig_path  = os.path.join(UPLOAD_FOLDER, "diff_orig_"  + original.filename)
    stego_path = os.path.join(UPLOAD_FOLDER, "diff_stego_" + stego.filename)
    diff_path  = os.path.join(OUTPUT_FOLDER, "diff_result_" + original.filename + ".png")

    original.save(orig_path)
    stego.save(stego_path)

    try:
        result = generate_visual_diff(orig_path, stego_path, diff_path)
        safe_remove(orig_path, stego_path)
        return jsonify(result)
    except ValueError as e:
        safe_remove(orig_path, stego_path)
        return error_response(str(e))
    except Exception as e:
        safe_remove(orig_path, stego_path)
        return error_response(f"Diff generation failed: {str(e)}", 500)

# ─── BATCH PROCESSING ────────────────────────────────────────────────────────

@app.route('/process/batch', methods=['POST'])
def process_batch():
    password  = request.form.get('password', '').strip()
    text      = request.form.get('text', '').strip()
    files     = request.files.getlist('files')
    bit_depth = int(request.form.get('bit_depth', 1))

    if not files or files[0].filename == '':
        return error_response("No files uploaded.")
    if not password or not text:
        return error_response("Passphrase and payload text are required.")

    memory_file = io.BytesIO()
    temp_paths  = []

    try:
        with zipfile.ZipFile(memory_file, 'w') as zf:
            for file in files:
                temp_in     = os.path.join(UPLOAD_FOLDER, "batch_in_" + file.filename)
                output_name = f"hidden_{file.filename}.png"
                output_path = os.path.join(OUTPUT_FOLDER, output_name)
                temp_paths.extend([temp_in, output_path])

                file.save(temp_in)
                encrypted = encrypt_data(text, password)
                hide_lsb(temp_in, encrypted, output_path, bit_depth=bit_depth)
                zf.write(output_path, arcname=output_name)

        safe_remove(*temp_paths)
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name="batch_stego_assets.zip"
        )
    except ValueError as e:
        safe_remove(*temp_paths)
        return error_response(str(e))
    except Exception as e:
        safe_remove(*temp_paths)
        return error_response(f"Batch processing failed: {str(e)}", 500)

# ─── PDF PROCESSING ──────────────────────────────────────────────────────────

@app.route('/process/pdf', methods=['POST'])
def process_pdf():
    mode     = request.form.get('mode')
    password = request.form.get('password', '').strip()
    file     = request.files.get('file')

    if not file or file.filename == '':
        return error_response("No PDF file provided.")
    if not password:
        return error_response("A passphrase is required.")

    filepath    = os.path.join(UPLOAD_FOLDER, file.filename)
    output_path = os.path.join(OUTPUT_FOLDER, "secret_" + file.filename)
    file.save(filepath)

    try:
        if mode == 'hide':
            text = request.form.get('text', '').strip()
            if not text:
                return error_response("Payload text is required for PDF injection.")
            encrypted = encrypt_data(text, password)
            hide_in_pdf(filepath, encrypted, output_path)
            return send_file(output_path, as_attachment=True)

        elif mode == 'extract':
            extracted_enc = extract_from_pdf(filepath)
            if extracted_enc == "No secret found.":
                return jsonify({"result": "No secret found in this PDF."})
            decrypted = decrypt_data(extracted_enc, password)
            return jsonify({"result": decrypted})

        else:
            return error_response(f"Unknown mode '{mode}'.")

    except ValueError as e:
        safe_remove(filepath, output_path)
        return error_response(str(e))
    except Exception as e:
        safe_remove(filepath, output_path)
        return error_response(f"PDF processing failed: {str(e)}", 500)

# ─── STATIC OUTPUT SERVING ───────────────────────────────────────────────────

@app.route('/outputs/<path:filename>')
def custom_static(filename):
    return send_from_directory(OUTPUT_FOLDER, filename)

# ─── WEBSOCKET — LIVE CHAT ───────────────────────────────────────────────────

@socketio.on('send_secure_msg')
def handle_send(data):
    """Receives {msg, password, carrier?, bit_depth?} → broadcasts stego image."""
    try:
        bit_depth = int(data.get('bit_depth', 1))
        encrypted_payload = encrypt_data(data['msg'], data['password'])

        if data.get('carrier'):
            header, encoded = (
                data['carrier'].split(",", 1)
                if "," in data['carrier']
                else (None, data['carrier'])
            )
            carrier_source = BytesIO(base64.b64decode(encoded))
        else:
            carrier_source = CARRIER_PATH

        buf = BytesIO()
        hide_lsb(carrier_source, encrypted_payload, buf, bit_depth=bit_depth)
        buf.seek(0)

        img_b64 = base64.b64encode(buf.read()).decode('utf-8')

        emit('sent_confirmation', {'status': 'SUCCESS'})
        emit('new_stego_packet',  {'image': img_b64, 'bit_depth': bit_depth},
             broadcast=True, include_self=False)

    except Exception as e:
        emit('error', {'message': str(e)})


@socketio.on('decrypt_packet')
def handle_decrypt(data):
    """Receives {image_b64, password, bit_depth?} → returns decrypted text."""
    try:
        bit_depth  = int(data.get('bit_depth', 1))
        img_data   = base64.b64decode(data['image'])
        img_buf    = BytesIO(img_data)

        extracted_enc  = extract_lsb(img_buf, bit_depth=bit_depth)
        decrypted_text = decrypt_data(extracted_enc, data['password'])
        emit('decrypted_result', {'msg': decrypted_text})

    except ValueError as e:
        emit('decrypted_result', {'msg': f"DECRYPTION_FAILED: {str(e)}"})
    except Exception:
        emit('decrypted_result', {'msg': "DECRYPTION_FAILED: Invalid key or corrupted packet."})


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)