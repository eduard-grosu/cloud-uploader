from flask import (
    Blueprint,
    render_template,
    request,
    make_response,
    redirect,
    url_for,
    jsonify,
    flash,
    send_file
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from . import db
from .models import File, User
import os
import base64
import uuid
import io


files = Blueprint('files', __name__)

upload_folder = 'uploads'
os.makedirs(upload_folder, exist_ok=True)


mime_types = {
    '.txt': 'text/plain',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.pdf': 'application/pdf'
}


def derive_key_from_password(master_password, salt):
    """Funcție pentru a obține o cheie dintr-o parolă principală și un salt"""

    password_bytes = master_password.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password_bytes)

    url_safe_key = base64.urlsafe_b64encode(key)
    return url_safe_key


def decrypt_file(password, file):
    key = derive_key_from_password(password, file.salt)

    with open(file.path, 'rb') as f:
        encrypted_data = f.read()

    try:
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_data)
    except Exception as e:
        print(f"Eroare de decriptare: {str(e)}")
        flash('Decryption error. Please contact the site administrator.')
        return redirect(url_for('files.files_index'))


@files.route('/files')
@login_required
def files_index():
    items = File.query.filter_by(email=current_user.email).all()
    return render_template('files.html', name=current_user.name, items=items)


@files.route('/files/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']

        name = secure_filename(file.filename)
        unique_id = uuid.uuid4().hex
        path = os.path.join(upload_folder, unique_id)

        # Generează un salt aleator pentru fiecare fișier
        salt = os.urandom(16)

        # Obține cheia de criptare din parola principală și salt
        key = derive_key_from_password(current_user.password, salt)

        # Creează un cifru Fernet folosind cheia derivată
        cipher = Fernet(key)

        # Citește datele fișierului
        file_data = file.read()

        # Criptează datele fișierului
        encrypted_data = cipher.encrypt(file_data)

        new_file = File(
            email=current_user.email,
            name=name,
            path=path,
            salt=salt,
            unique_id=unique_id
        )

        db.session.add(new_file)
        db.session.commit()

        # Salvează fișierul criptat pe disk
        with open(path, 'wb') as f:
            f.write(encrypted_data)

    return redirect(url_for('files.files_index'))


@files.route('/files/download/<unique_id>')
def download(unique_id):
    obj = db.session.query(
        User, File
    ).filter(
        User.email == File.email
    ).filter(
        File.unique_id == unique_id
    ).all()

    if not obj:
        flash('File not found.')
        return redirect(url_for('files.files_index'))

    user, file = obj[0]
    if not (current_user.is_authenticated and current_user.email == file.email) and not file.is_public:
        flash('Please log in to access this page.')
        return redirect(url_for('auth.login'))

    decrypted_data = decrypt_file(user.password, file)
    response = make_response(decrypted_data)

    # Setează tipul de conținut și anteturile potrivite pentru fișier
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="{file.name}"'

    return response


@files.route('/files/preview/<unique_id>')
def preview(unique_id):
    obj = db.session.query(
        User, File
    ).filter(
        User.email == File.email
    ).filter(
        File.unique_id == unique_id
    ).all()

    if not obj:
        flash('File not found.')
        return redirect(url_for('files.files_index'))

    user, file = obj[0]
    if not (current_user.is_authenticated and current_user.email == file.email) and not file.is_public:
        flash('Please log in to access this page.')
        return redirect(url_for('auth.login'))

    decrypted_data = decrypt_file(user.password, file)
    if file.name.endswith(tuple(mime_types.keys())):
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype=mime_types[os.path.splitext(file.name)[1]]
        )

    flash('This file cannot be previewed.')
    return redirect(url_for('files.files_index'))


@files.route('/files/delete/<unique_id>')
@login_required
def delete(unique_id):
    file = File.query.filter_by(unique_id=unique_id, email=current_user.email).first()
    if not file:
        flash('File not found.')
        return redirect(url_for('files.files_index'))

    db.session.delete(file)
    db.session.commit()
    
    # remove file from disk as well
    os.remove(file.path)

    return redirect(url_for('files.files_index'))


@files.route('/files/update/<unique_id>', methods=['POST'])
@login_required
def update(unique_id):
    file = File.query.filter_by(unique_id=unique_id, email=current_user.email).first()
    if not file:
        flash('File not found.')
        return redirect(url_for('files.files_index'))

    json_data = request.get_json()
    file.name = secure_filename(json_data['newName'])
    file.is_public = json_data['makePublic']

    db.session.commit()

    return redirect(url_for('files.files_index'))
