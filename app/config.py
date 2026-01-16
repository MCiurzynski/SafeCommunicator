import os
import redis

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
class Config:
    SECRET_KEY = os.environ['SECRET_KEY']
    TOTP_ENCRYPTION_KEY = os.environ['TOTP_ENCRYPTION_KEY']
    db_user = os.environ['POSTGRES_USER']
    db_pass = os.environ['POSTGRES_PASSWORD']
    db_name = os.environ['POSTGRES_DB']
    db_host = os.environ['DB_HOST']

    MAX_CONTENT_LENGTH = int(os.environ['MAX_CONTENT_LENGTH'])

    RATELIMIT_STORAGE_URI = os.environ['REDIS_URI']

    SQLALCHEMY_DATABASE_URI = f"postgresql://{db_user}:{db_pass}@{db_host}:5432/{db_name}"

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/app/uploads')

    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_REDIS = SESSION_REDIS = redis.from_url(os.environ['REDIS_URI'])