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
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
socketio = SocketIO(app, cors_allowed_origins="*")
CARRIER_PATH = "static/favicon.ico.png"

for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# ─── HELPERS ────────────────────────────────────────────────

def safe_remove(*paths):
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except OSError:
            pass

def error_response(message, code=400):
    return jsonify({"error": message}), code

# ─── NAVIGATION ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/local')
def local_toolkit():
    return render_template('local.html')

@app.route('/live')
def live_chat():
    return render_template('live.html')

# ─── IMAGE STEGANOGRAPHY ─────────────────────────────────────

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
            return error_response(f"Unknown mode '{mode}'.")

    except ValueError as e:
        safe_remove(filepath, output_path)
        return error_response(str(e))
    except Exception as e:
        safe_remove(filepath, output_path)
        return error_response(f"Unexpected error: {str(e)}", 500)

# ─── ANOMALY DETECTION ───────────────────────────────────────

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

# ─── CAPACITY CHECK ──────────────────────────────────────────

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

# ─── VISUAL DIFF ─────────────────────────────────────────────

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

# ─── EXIF METADATA STRIP ─────────────────────────────────────

@app.route('/process/strip', methods=['POST'])
def strip_metadata():
    """
    Strips ALL metadata (EXIF, GPS, ICC profile, comments) from an image
    by re-encoding it through Pillow with no metadata attached.
    Returns a clean PNG with only raw pixel data.
    """
    file = request.files.get('file')
    if not file or file.filename == '':
        return error_response("No file provided.")

    filepath    = os.path.join(UPLOAD_FOLDER, "strip_" + file.filename)
    output_path = os.path.join(OUTPUT_FOLDER,  "clean_" + os.path.splitext(file.filename)[0] + ".png")
    file.save(filepath)

    try:
        # Open and immediately re-save via a clean pixel buffer — no metadata carried over
        img = Image.open(filepath).convert("RGB")

        # Collect original metadata stats before stripping
        original_info = img.info  # dict of all metadata fields
        exif_data     = img.getexif() if hasattr(img, 'getexif') else {}
        fields_removed = len(original_info) + len(exif_data)

        # Save as a fresh PNG with zero extra data
        clean_img = Image.fromarray(__import__('numpy').array(img))
        clean_img.save(output_path, format="PNG")

        safe_remove(filepath)

        original_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        clean_size    = os.path.getsize(output_path)

        return send_file(
            output_path,
            as_attachment=True,
            download_name=f"clean_{os.path.splitext(file.filename)[0]}.png",
        )

    except Exception as e:
        safe_remove(filepath, output_path)
        return error_response(f"Strip failed: {str(e)}", 500)


@app.route('/process/strip_info', methods=['POST'])
def strip_metadata_info():
    """
    Returns a JSON preview of what metadata WOULD be stripped,
    without modifying or downloading anything.
    """
    file = request.files.get('file')
    if not file or file.filename == '':
        return error_response("No file provided.")

    filepath = os.path.join(UPLOAD_FOLDER, "stripinfo_" + file.filename)
    file.save(filepath)

    try:
        img  = Image.open(filepath)
        info = img.info or {}

        # Parse EXIF tag names if available
        exif_fields = {}
        try:
            from PIL.ExifTags import TAGS
            raw_exif = img.getexif()
            exif_fields = {TAGS.get(k, str(k)): str(v)[:80] for k, v in raw_exif.items()}
        except Exception:
            pass

        safe_remove(filepath)

        return jsonify({
            "format":       img.format or "Unknown",
            "mode":         img.mode,
            "size":         f"{img.width}×{img.height}",
            "info_fields":  {k: str(v)[:80] for k, v in info.items()},
            "exif_fields":  exif_fields,
            "total_fields": len(info) + len(exif_fields),
        })

    except Exception as e:
        safe_remove(filepath)
        return error_response(f"Metadata read failed: {str(e)}", 500)

# ─── BATCH PROCESSING ────────────────────────────────────────

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

# ─── PDF PROCESSING ──────────────────────────────────────────

@app.route('/process/pdf', methods=['POST'])
def process_pdf():
    mode = request.form.get('mode')
    password = request.form.get('password', '').strip()
    file = request.files.get('file')

    if not file or file.filename == '':
        return error_response("No PDF file provided.")
    if not password:
        return error_response("A passphrase is required.")

    # Secure the filename to prevent directory traversal attacks
    from werkzeug.utils import secure_filename
    clean_name = secure_filename(file.filename)
    
    filepath = os.path.join(UPLOAD_FOLDER, clean_name)
    output_path = os.path.join(OUTPUT_FOLDER, "secret_" + clean_name)
    file.save(filepath)

    try:
        if mode == 'hide':
            text = request.form.get('text', '').strip()
            if not text:
                return error_response("Payload text is required.")
            
            encrypted = encrypt_data(text, password)
            hide_in_pdf(filepath, encrypted, output_path)
            
            # Use a 'finally' style cleanup or send_file will block deletion
            return send_file(output_path, as_attachment=True)

        elif mode == 'extract':
            extracted_enc = extract_from_pdf(filepath)
            
            if extracted_enc == "No secret found.":
                return jsonify({"result": "No secret found in this PDF."})
            
            decrypted = decrypt_data(extracted_enc, password)
            
            # Clean up the upload after extraction
            if os.path.exists(filepath):
                os.remove(filepath)
                
            return jsonify({"result": decrypted})

        else:
            return error_response(f"Unknown mode '{mode}'.")

    except Exception as e:
        # Ensure files are removed if something crashes mid-process
        if os.path.exists(filepath): os.remove(filepath)
        if os.path.exists(output_path): os.remove(output_path)
        return error_response(f"PDF Error: {str(e)}", 500)

# ─── STATIC OUTPUT SERVING ───────────────────────────────────

@app.route('/outputs/<path:filename>')
def custom_static(filename):
    return send_from_directory(OUTPUT_FOLDER, filename)

# ─── WEBSOCKET — ROOM-BASED LIVE CHAT ────────────────────────

@socketio.on('join_room')
def handle_join(data):
    """User joins a named room. Broadcasts join notice to room members."""
    room     = data.get('room', '').strip().upper()
    codename = data.get('codename', 'UNKNOWN')
    if not room:
        emit('error', {'message': 'Room code is required.'})
        return

    join_room(room)
    emit('room_joined', {'room': room, 'codename': codename})
    emit('room_event', {
        'type':     'join',
        'codename': codename,
        'room':     room,
        'message':  f"{codename} joined the channel."
    }, to=room, include_self=False)


@socketio.on('leave_room')
def handle_leave(data):
    room     = data.get('room', '').strip().upper()
    codename = data.get('codename', 'UNKNOWN')
    if room:
        leave_room(room)
        emit('room_event', {
            'type':     'leave',
            'codename': codename,
            'room':     room,
            'message':  f"{codename} left the channel."
        }, to=room)


@socketio.on('send_secure_msg')
def handle_send(data):
    try:
        room      = data.get('room', '').strip().upper()
        codename  = data.get('codename', 'GHOST')
        bit_depth = int(data.get('bit_depth', 1))
        # Get the file type sent from live.html
        file_type = data.get('file_type', 'image/png') 

        if not room:
            emit('error', {'message': 'Must join a room before sending.'})
            return

        # 1. Encrypt the secret message regardless of file type
        encrypted_payload = encrypt_data(data['msg'], data['password'])

        # 2. Decode the incoming carrier
        header, encoded = (
            data['carrier'].split(",", 1)
            if data.get('carrier') and "," in data['carrier']
            else (None, data.get('carrier'))
        )
        
        # If no carrier is provided, we default to the standard image CARRIER_PATH
        if not encoded:
            carrier_bytes = open(CARRIER_PATH, "rb").read()
        else:
            carrier_bytes = base64.b64decode(encoded)

        # 3. Process based on File Type
        output_buf = BytesIO()

        if "application/pdf" in file_type:
            # --- PDF LOGIC ---
            from pdf.pdf_crypto import hide_in_pdf
            # Create temp paths because PyPDF2 works best with file handles or paths
            temp_in = os.path.join(UPLOAD_FOLDER, f"temp_{codename}.pdf")
            temp_out = os.path.join(OUTPUT_FOLDER, f"stego_{codename}.pdf")
            
            with open(temp_in, "wb") as f:
                f.write(carrier_bytes)
            
            # Inject secret into metadata
            hide_in_pdf(temp_in, encrypted_payload, temp_out)
            
            with open(temp_out, "rb") as f:
                output_buf.write(f.read())
            
            # Cleanup temp files
            if os.path.exists(temp_in): os.remove(temp_in)
            if os.path.exists(temp_out): os.remove(temp_out)
            
        else:
            # --- IMAGE LSB LOGIC ---
            carrier_source = BytesIO(carrier_bytes)
            hide_lsb(carrier_source, encrypted_payload, output_buf, bit_depth=bit_depth)

        # 4. Finalize and Broadcast
        output_buf.seek(0)
        final_b64 = base64.b64encode(output_buf.read()).decode('utf-8')

        emit('sent_confirmation', {'status': 'SUCCESS', 'room': room})
        emit('new_stego_packet', {
            'image':     final_b64, # We use the 'image' key for both for simplicity
            'file_type': file_type, # Tell the receiver what this is!
            'bit_depth': bit_depth,
            'codename':  codename,
            'room':      room,
        }, to=room, include_self=False)

    except Exception as e:
        emit('error', {'message': f"Socket Error: {str(e)}"})


@socketio.on('decrypt_packet')
def handle_decrypt(data):
    try:
        password = data.get('password')
        file_type = data.get('file_type', 'image/png')
        
        # Decode the incoming base64
        header, encoded = (
            data['image'].split(",", 1) 
            if "," in data['image'] 
            else (None, data['image'])
        )
        file_bytes = base64.b64decode(encoded)

        if "application/pdf" in file_type:
            # --- PDF EXTRACTION LOGIC ---
            from pdf.pdf_crypto import extract_from_pdf
            
            # Save to a temp file so PdfReader can process it
            temp_path = os.path.join(UPLOAD_FOLDER, "temp_decrypt.pdf")
            with open(temp_path, "wb") as f:
                f.write(file_bytes)
            
            # Extract the encrypted string from metadata
            encrypted_str = extract_from_pdf(temp_path)
            os.remove(temp_path) # Clean up immediately
            
            if encrypted_str == "No secret found.":
                emit('decrypted_result', {'msg': "No secret found."})
                return
                
            # Decrypt the string using your AES logic
            decrypted_msg = decrypt_data(encrypted_str, password)
            
        else:
            # --- IMAGE LSB LOGIC ---
            from io import BytesIO
            # Your existing LSB extraction logic goes here
            # decrypted_msg = extract_lsb_and_decrypt(BytesIO(file_bytes), password)
            pass

        emit('decrypted_result', {'msg': decrypted_msg})

    except Exception as e:
        # This is where your "Decryption failed" message is coming from
        emit('decrypted_result', {'msg': f"Decryption failed: {str(e)}"})


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)