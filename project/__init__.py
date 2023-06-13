from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '[{asctime}] [{levelname:<7}] {name}: {message}',
            'datefmt': '%d-%m-%Y %H:%M:%S',
            'style': '{'
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'default'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'flask.log',
            'formatter': 'default',
            'maxBytes': 10**6*5, # 5mb
            'backupCount': 3
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': [
            'wsgi',
            'file'
        ]
    }
})


db = SQLAlchemy()
sessions = dict()


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'some-secret-key-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .files import files as files_blueprint
    app.register_blueprint(files_blueprint)

    return app
