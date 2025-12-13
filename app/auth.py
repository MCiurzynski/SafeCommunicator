from flask import Blueprint, render_template, redirect, url_for
from passlib.hash import argon2
from app.forms import LoginForm, RegisterForm
from app.db import db, User
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute()
        if user.check_password(form.password.data)
    return render_template('login.html', form=form)

@bp.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        key_pair = RSA.generate(4096)
        pub_key_pem = key_pair.public_key().export_key().decode('utf-8')
        
        priv_key_encrypted = key_pair.export_key(
            passphrase=form.password_first.data, 
            pkcs=8, 
            protection='scryptAndAES256-CBC'
        ).decode('utf-8')

        pass_hash = argon2.hash(form.password_first.data)

        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=pass_hash,
            public_key=pub_key_pem,
            encrypted_private_key=priv_key_encrypted
        )
        
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html', form=form)