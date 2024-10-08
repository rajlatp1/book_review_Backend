# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from app.config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)   
    app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False


    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    CORS(app, supports_credentials=True)

    with app.app_context():
        from app import routes
        app.register_blueprint(routes.bp)

        db.create_all()

    return app
