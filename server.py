from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import base64
from io import BytesIO
from PIL import Image
import os

# Import your existing modules
import aes
import lsb

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# A default blank image to use as a carrier if the user doesn't upload one
CARRIER_PATH = "static/assets/default_carrier.png" 

@app.route('/')
def index():
    return render_template('index.html') # Your new Homepage with 2 cards

@app.route('/live')
def live_chat():
    return render_template('live.html') # The Live Chat UI

@socketio.on('send_secure_msg')
def handle_send_msg(data):
    """
    Data contains: {'msg': 'hello', 'password': '123'}
    """
    try:
        # 1. Encrypt
        encrypted_payload = aes.encrypt_data(data['msg'], data['password'])
        
        # 2. Hide in Image (LSB)
        # Using a temporary file for the stego process
        temp_output = "temp_stego.png"
        lsb.hide_lsb(CARRIER_PATH, encrypted_payload, temp_output)
        
        # 3. Convert Image to Base64 to send over Socket
        with open(temp_output, "rb") as img_file:
            b64_string = base64.b64encode(img_file.read()).decode('utf-8')
        
        # 4. Broadcast to everyone
        emit('new_stego_packet', {'image': b64_string}, broadcast=True)
        
        # Cleanup
        if os.path.exists(temp_output): os.remove(temp_output)
        
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('decrypt_packet')
def handle_decrypt(data):
    """
    Data contains: {'image': 'base64...', 'password': '123'}
    """
    try:
        # 1. Save incoming B64 to temp file
        header, encoded = data['image'].split(",", 1) if "," in data['image'] else (None, data['image'])
        with open("temp_incoming.png", "wb") as f:
            f.write(base64.b64decode(encoded))
            
        # 2. Extract LSB
        encrypted_payload = lsb.extract_lsb("temp_incoming.png")
        
        # 3. AES Decrypt
        decrypted_text = aes.decrypt_data(encrypted_payload, data['password'])
        
        emit('decrypted_result', {'msg': decrypted_text})
    except Exception as e:
        emit('decrypted_result', {'msg': "Decryption failed: Incorrect Key"})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)