from flask import Blueprint, render_template, redirect, url_for, session
from app.forms import LoginForm, RegisterForm
from app.db import db, User
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from flask_login import current_user, login_user, logout_user

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
        db.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index.index'))
    return render_template('login.html', form=form)

@bp.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        key_pair = RSA.generate(4096)
        pub_key_pem = key_pair.public_key().export_key().decode('utf-8')
        
        priv_key_encrypted = key_pair.export_key(
            passphrase=form.password_first.data, 
            pkcs=8, 
            protection='PBKDF2WithHMAC-SHA512AndAES256-CBC'
        ).decode('utf-8')

        user = User(
            username=form.username.data,
            email=form.email.data,
            public_key=pub_key_pem,
            encrypted_private_key=priv_key_encrypted
        )
        
        user.set_password(form.password_first.data)

        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index.index'))
    return render_template('register.html', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index.index'))