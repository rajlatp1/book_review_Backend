from flask import Flask
from flask_cors import CORS
from app.config import Config
from app.models import init_db
from app.routes import routes

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)
    init_db(app)
    app.register_blueprint(routes)
    return app
