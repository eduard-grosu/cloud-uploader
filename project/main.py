from flask import Blueprint, render_template
from flask_login import login_required, current_user
from . import db
from datetime import datetime

main = Blueprint('main', __name__)

date = datetime.now().strftime('%H:%M:%S - %d-%m-%Y')

@main.route('/')
def index():
    return render_template('index.html', date=date)
