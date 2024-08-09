# app/config.py
class Config:
    SECRET_KEY = 'secret_key'
    JWT_SECRET_KEY = 'jwt_secret_key'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:root@localhost/book_review_platform'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
