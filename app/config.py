import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    TOTP_ENCRYPTION_KEY = os.environ.get('TOTP_ENCRYPTION_KEY')
    db_user = os.environ.get('POSTGRES_USER')
    db_pass = os.environ.get('POSTGRES_PASSWORD')
    db_name = os.environ.get('POSTGRES_DB')
    db_host = os.environ.get('DB_HOST')

    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH'))

    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI')

    SQLALCHEMY_DATABASE_URI = f"postgresql://{db_user}:{db_pass}@{db_host}:5432/{db_name}"

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/app/uploads')