from flask import (
    Blueprint,
    render_template,
    request,
    make_response,
    redirect,
    url_for,
    jsonify,
    flash
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from . import db
from .models import File
import os
import base64

files = Blueprint('files', __name__)


# Funcție pentru a obține o cheie dintr-o parolă principală și un salt
def derive_key_from_password(master_password, salt):
    password_bytes = master_password.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password_bytes)

    # Asigură-te că cheia derivată este codificată în format URL-safe base64
    url_safe_key = base64.urlsafe_b64encode(key)

    return url_safe_key


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

        # Generează un nume de fișier unic
        filename = secure_filename(file.filename)

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

        new_file = File(email=current_user.email, filename=filename, content=encrypted_data, salt=salt)

        db.session.add(new_file)
        db.session.commit()

    return redirect(url_for('files.files_index'))

@files.route('/files/download/<file_id>')
@login_required
def download(file_id):
    file = File.query.filter_by(id=file_id, email=current_user.email).first()

    if file:
        encrypted_data = file.content
        salt = file.salt

        # Obține cheia de criptare folosind parola principală și saltul stocat
        key = derive_key_from_password(current_user.password, salt)

        try:
            # Creează un cifru Fernet folosind cheia derivată
            cipher = Fernet(key)

            # Decriptează datele fișierului
            decrypted_data = cipher.decrypt(encrypted_data)

            # Creează un răspuns cu datele fișierului decriptat
            response = make_response(decrypted_data)

            # Setează tipul de conținut și anteturile potrivite pentru fișier
            response.headers['Content-Type'] = 'application/octet-stream'
            response.headers['Content-Disposition'] = f'attachment; filename="{file.filename}"'

            return response
        except Exception as e:
            # Gestionează erorile de decriptare
            print(f"Eroare de decriptare: {str(e)}")
            flash('Decryption error. Please contact the site administrator.')
            return redirect(url_for('files.files_index'))
    else:
        flash('File not found.')
        return redirect(url_for('files.files_index'))

@files.route('/files/delete/<file_id>')
@login_required
def delete(file_id):
    file = File.query.filter_by(id=file_id, email=current_user.email).first()
    if file:
        db.session.delete(file)
        db.session.commit()
        return redirect(url_for('files.files_index'))
    
    flash('File not found.')
    return redirect(url_for('files.files_index'))
