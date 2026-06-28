import os
import uuid
from flask import Flask, request, jsonify, send_from_directory, abort, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/')
def index():
    return render_template( 'index.html')



@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Receives encrypted payload and metadata, saves to disk, returns reference id."""
    if 'file' not in request.files:
        return jsonify({"error": "No file payload found"}), 400
    
    file_blob = request.files['file']
    file_id = str(uuid.uuid4())
    
    # Store encrypted file
    file_path = os.path.join(UPLOAD_DIR, file_id)
    file_blob.save(file_path)
    
    # Store client-supplied original filename (encrypted string) & iv
    original_name = request.form.get('filename', 'encrypted_payload')
    iv = request.form.get('iv', '')
    
    metadata_path = file_path + '.meta'
    with open(metadata_path, 'w', encoding='utf-8') as f:
        f.write(f"{original_name}\n{iv}")

    return jsonify({
        "success": True,
        "id": file_id,
        "download_url": f"{request.host_url}#download/{file_id}"
    })

@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """Retrieves encrypted payload and matching initialization vector."""
    # Prevent directory traversal
    safe_file_id = os.path.basename(file_id)
    file_path = os.path.join(UPLOAD_DIR, safe_file_id)
    meta_path = file_path + '.meta'
    
    if not os.path.exists(file_path) or not os.path.exists(meta_path):
        return jsonify({"error": "Resource not found or expired"}), 404
        
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta_lines = f.read().splitlines()
        
    encrypted_filename = meta_lines[0] if len(meta_lines) > 0 else 'encrypted_payload'
    iv = meta_lines[1] if len(meta_lines) > 1 else ''
    
    # Respond with file blob along with headers containing IV and target encrypted name
    response = send_from_directory(UPLOAD_DIR, safe_file_id, as_attachment=True)
    response.headers['X-Encrypted-Filename'] = encrypted_filename
    response.headers['X-Crypto-IV'] = iv
    
    # Optional auto-deletion to maintain "ephemeral zero-knowledge" design
    # In a full production build, you can schedule deletions.
    return response

if __name__ == '__main__':
    print("ZeroShare starting on http://localhost:5000")
    app.run(port=5000, debug=True)
