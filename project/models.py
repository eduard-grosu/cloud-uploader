from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.Text, unique=True)
    password = db.Column(db.Text)
    name = db.Column(db.Text)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, db.ForeignKey('user.email'))
    
    name = db.Column(db.Text)
    path = db.Column(db.Text)
    salt = db.Column(db.LargeBinary)

    is_public = db.Column(db.Boolean, default=False)
    unique_id = db.Column(db.Text, default=None)
