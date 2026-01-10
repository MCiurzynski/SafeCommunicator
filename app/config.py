import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    TOTP_ENCRYPTION_KEY = os.environ.get('TOTP_ENCRYPTION_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')