import os
import urllib.request
import ipfshttpclient
from flask_session import Session
from my_constants import app
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify
from flask_socketio import SocketIO, send, emit
from werkzeug.utils import secure_filename
import socket
import pickle
from blockchain import Blockchain
import requests
from flask import session 
from flask import request  
from werkzeug.security import check_password_hash
from auth import auth as auth_blueprint
from flask_sqlalchemy import SQLAlchemy
from database import db, DownloadRequest
from flask import get_flashed_messages
from datetime import datetime
import json
from dotenv import load_dotenv

load_dotenv()

PINATA_API_KEY = os.getenv("PINATA_API_KEY")
PINATA_SECRET_API_KEY = os.getenv("PINATA_SECRET_API_KEY")
PINATA_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS"

app = Flask(__name__, static_folder='static')

app.config['BUFFER_SIZE'] = 64 * 1024  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()
    pending_requests = DownloadRequest.query.filter_by(status="Pending").all()
    print("DEBUG: Pending Requests in DB:", pending_requests)  

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'upload')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = 'downloads'
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.secret_key = 'your_very_secret_key'  
app.config['SESSION_TYPE'] = 'filesystem'  
app.config['SESSION_PERMANENT'] = False  
app.config['SESSION_USE_SIGNER'] = True  
app.config['SESSION_KEY_PREFIX'] = 'blockchain_'  
Session(app)  
app.register_blueprint(auth_blueprint, url_prefix='/auth')
socketio = SocketIO(app)
blockchain = Blockchain()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def append_file_extension(uploaded_file, file_path):
    file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
    user_file = open(file_path, 'a')
    user_file.write('\n' + file_extension)
    user_file.close()

def decrypt_file(file_path, file_key):
    encrypted_file = file_path + ".aes"
    os.rename(file_path, encrypted_file)
    pyAesCrypt.decryptFile(encrypted_file, file_path,  file_key, app.config['BUFFER_SIZE'])

def encrypt_file(file_path, file_key):
    pyAesCrypt.encryptFile(file_path, file_path + ".aes",  file_key, app.config['BUFFER_SIZE'])
    os.remove(file_path)
def hash_user_file(file_path, file_key):
    encrypt_file(file_path, file_key)
    encrypted_file_path = file_path + ".aes"

    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }

    filename = os.path.basename(file_path)  # Get the original filename

    metadata = {
        "name": filename,  # Store filename as metadata
    }

    with open(encrypted_file_path, 'rb') as file:
        files = {"file": file}
        payload = {"pinataMetadata": json.dumps(metadata)}

        response = requests.post(PINATA_URL, headers=headers, files=files, data=payload)

    if response.status_code == 200:
        file_hash = response.json()["IpfsHash"]
        print(f"✅ File uploaded to Pinata: {file_hash} (Original: {filename})")
        return file_hash, filename  # Return hash + original filename
    else:
        print("❌ Pinata Upload Failed:", response.text)
        return None, None

def retrieve_from_hash(file_hash, file_key):
    # Pinata Gateway URL
    url = f"https://gateway.pinata.cloud/ipfs/{file_hash}"
    response = requests.get(url)

    if response.status_code == 200:
        file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)

        with open(file_path, "wb") as file:
            file.write(response.content)

        decrypt_file(file_path, file_key)

        # Retrieve metadata (original filename)
        metadata_url = f"https://api.pinata.cloud/data/pinList?hashContains={file_hash}"
        headers = {
            "pinata_api_key": PINATA_API_KEY,
            "pinata_secret_api_key": PINATA_SECRET_API_KEY
        }
        metadata_response = requests.get(metadata_url, headers=headers)
        
        if metadata_response.status_code == 200:
            metadata = metadata_response.json()
            if metadata["rows"]:
                original_filename = metadata["rows"][0]["metadata"]["name"]
                extension = original_filename.split(".")[-1]  # Extract extension
                restored_file_path = f"{file_path}.{extension}"  # Append correct extension
                
                os.rename(file_path, restored_file_path)  # Rename the file
                
                print(f"✅ File restored as: {restored_file_path}")
                return restored_file_path
        
        print("⚠️ Metadata not found, file saved without extension.")
        return file_path

    else:
        print("❌ Error fetching from Pinata:", response.text)
        return None



def get_unique_flashed_messages():
    """Remove duplicate flash messages."""
    messages = get_flashed_messages(with_categories=True)
    unique_messages = list(dict.fromkeys(messages)) 
    return unique_messages

@app.before_request
def check_authentication():
    allowed_routes = ['auth.login', 'auth.register', 'static', 'get_chain']

    print("Session Data:", dict(session))  

    if request.endpoint == 'auth.login' and session.get('username'):
        return redirect(url_for('home'))  

    if not session.get('username') and request.endpoint not in allowed_routes:
        return redirect(url_for('auth.login'))

@app.route('/blockchain_activity')
def blockchain_activity():
    formatted_blocks = []
    
    for block in blockchain.chain:
        transactions = [{
            'sender': block.get('sender', 'N.A'),
            'receiver': block.get('receiver', 'N.A'),
            'file_hash': block.get('shared_files', 'N.A'),
            'uploaded_by': block.get('sender', 'N.A')  
        }]
        
        formatted_blocks.append({
            'index': block['index'],
            'timestamp': block['timestamp'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
            'transactions': transactions  
        })
    
    return render_template('blockchain_activity.html', blockchain_logs=formatted_blocks)

@app.route('/auth/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password): 
        flash("Invalid credentials. Please try again.", "danger")
        return redirect(url_for('auth.login'))
    session['username'] = user.username
    session['role'] = user.role
    flash("✅ Login successful!", "success")  
    if user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('index'))
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    return render_template('index.html')


@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/upload')
def upload():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    return render_template('upload.html')

@app.route('/download')
def download():
    return render_template('download.html')

@app.route('/connect_blockchain')
def connect_blockchain():
    is_chain_replaced = blockchain.replace_chain()
    return render_template('connect_blockchain.html', chain = blockchain.chain, nodes = len(blockchain.nodes))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
    pending_requests = DownloadRequest.query.filter_by(status="Pending").all()
    logs = DownloadRequest.query.filter(DownloadRequest.status != "Pending").order_by(DownloadRequest.timestamp.desc()).all()
    print("DEBUG: Showing pending requests:", pending_requests)
    print("DEBUG: Showing logs:", logs)
    return render_template('admin_dashboard.html', requests=pending_requests, logs=logs)

@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
    request_entry = DownloadRequest.query.get(request_id)
    if request_entry:
        request_entry.status = "Approved"
        request_entry.timestamp = datetime.utcnow()  
        db.session.commit()
        flash("✅ Request approved!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
    request_entry = DownloadRequest.query.get(request_id)
    if request_entry:
        request_entry.status = "Rejected"
        request_entry.timestamp = datetime.utcnow()  
        db.session.commit()
        flash("❌ Request rejected! The user can try again.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.errorhandler(413)
def entity_too_large(e):
    return render_template('upload.html' , message = "Requested Entity Too Large!")

@app.route('/add_file', methods=['POST'])
def add_file():
    
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        print('The nodes had different chains so the chain was replaced by the longest one.')
    else:
        print('All good. The chain is the largest one.')

    if request.method == 'POST':
        error_flag = True
        if 'file' not in request.files:
            message = 'No file part'
        else:
            user_file = request.files['file']
            if user_file.filename == '':
                message = 'No file selected for uploading'

            if user_file and allowed_file(user_file.filename):
                error_flag = False
                filename = secure_filename(user_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                user_file.save(file_path)
                append_file_extension(user_file, file_path)
                sender = request.form['sender_name']
                receiver = request.form['receiver_name']
                file_key = request.form['file_key']

                try:
                    hashed_output1 = hash_user_file(file_path, file_key)
                    index = blockchain.add_file(sender, receiver, hashed_output1)
                except Exception as err:
                    message = str(err)
                    error_flag = True
                    if "ConnectionError:" in message:
                        message = "Gateway down or bad Internet!"

            else:
                error_flag = True
                message = 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'
    
        if error_flag == True:
            return render_template('upload.html' , message = message)
        else:
            flash("✅ File uploaded successfully!", "success")
            return redirect(url_for('upload'))

@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    username = session['username']
    file_hash = request.form['file_hash']
    file_key = request.form['file_key']

    request_status = DownloadRequest.query.filter_by(username=username, file_hash=file_hash).first()

    if request_status is None:
        new_request = DownloadRequest(username=username, file_hash=file_hash, status="Pending", timestamp=datetime.utcnow())
        db.session.add(new_request)
        db.session.commit()
        flash("✅ Your download request has been sent to the admin for approval.", "info")
        return redirect(url_for('download'))

    elif request_status.status == "Pending":
        flash("⏳ Your request is still pending approval. Please wait.", "warning")
        return redirect(url_for('download'))

    elif request_status.status == "Rejected":
    # Delete the old rejected request and create a new one
        db.session.delete(request_status)
        db.session.commit()

        new_request = DownloadRequest(username=username, file_hash=file_hash, status="Pending", timestamp=datetime.utcnow())
        db.session.add(new_request)
        db.session.commit()

        flash("✅ Your new download request has been sent to the admin for approval.", "info")
        return redirect(url_for('download'))


    file_path = retrieve_from_hash(file_hash, file_key)
    return send_file(file_path, as_attachment=True)


@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    print(request)

@socketio.on('add_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.add(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('remove_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.remove(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    print(request)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5111, debug=True)

