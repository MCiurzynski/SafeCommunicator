from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, jsonify
from app.forms import LoginForm, RegisterForm, ResetPasswordForm, ChangePasswordForm
from app.db import db, User, ResetPassword
from flask_login import current_user, login_user, logout_user, login_required
import pyotp
import qrcode
import io
from app import limiter
import base64
import secrets
from passlib.hash import argon2
from datetime import datetime, timedelta

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/login', methods=['POST', 'GET'])
@limiter.limit("50 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        
        user = db.session.scalar(
            db.select(User).where(User.username == form.username.data)
        )

        error_msg = "Nieprawidłowy login, hasło lub kod 2FA"

        if user is None:
            return jsonify({'success': False, 'message': error_msg}), 401
        
        if not user.check_password(form.password_verifier.data):
            return jsonify({'success': False, 'message': error_msg}), 401

        if user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(form.totp_code.data, valid_window=1):
                return jsonify({'success': False, 'message': error_msg}), 401
        
        login_user(user)
        
        return jsonify({
            'success': True,
            'redirect_url': url_for('main.index'),
            'keys': {
                'encrypted_private_key': user.encrypted_private_key,
                'private_key_iv': user.private_key_iv,
                'encrypted_signing_private_key': user.encrypted_signing_private_key,
                'signing_private_key_iv': user.signing_private_key_iv
            }
        })

    if request.method == 'POST' and not form.validate():
        return jsonify({'success': False, 'message': "Error"}), 400

    return render_template('login.html', form=form)


@bp.route('/register', methods=['POST', 'GET'])
@limiter.limit("50 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        if form.website.data:
            print(f"BOT DETECTED: {request.remote_addr} filled honeypot.")
            return redirect(url_for('main.index'))

        new_totp_secret = pyotp.random_base32()

        user = User(
            username=form.username.data,
            email=form.email.data,
            
            public_key=form.public_key.data,
            encrypted_private_key=form.encrypted_private_key.data,
            private_key_iv=form.private_key_iv.data,
            
            signing_public_key=form.signing_public_key.data,
            encrypted_signing_private_key=form.encrypted_signing_private_key.data,
            signing_private_key_iv=form.signing_private_key_iv.data,
            
            totp_secret=new_totp_secret
        )
        
        user.set_password(form.password_verifier.data)

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('auth.setup_2fa'))

    return render_template('register.html', form=form)


@bp.route('/setup-2fa')
@login_required
def setup_2fa():
    user = current_user
    if not user.totp_secret:
        return redirect(url_for('main.index'))

    uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name="SecureChat"
    )

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_2fa.html', qr_code=img_base64, secret=user.totp_secret)


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/regenerate_2fa')
@login_required
def regenerate_2fa():
    user = current_user
    new_totp_secret = pyotp.random_base32()
    user.totp_secret = new_totp_secret
    db.session.commit()
    return redirect(url_for('auth.setup_2fa'))

@bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    expiration_period = 15 # minutes

    form = ResetPasswordForm()
    if form.validate_on_submit():
        token = secrets.token_urlsafe(32)
        hash_token = argon2.hash(token)
        expires_at = datetime.now() + timedelta(minutes=expiration_period)
        user = db.session.scalar(
            db.select(User).where(User.username == form.username.data)
        )
        if user is not None:
            reset_pass = ResetPassword(
                user = user,
                token_hash = hash_token,
                expires_at = expires_at,
            )
            db.session.add(reset_pass)
            db.session.commit()
            link = url_for('auth.set_new_password', token=token, username=user.username, _external=True)
            log = f'Użytkownik poprosił o zmianę hasła, wysłałbym mu link: {link} na adres e-mail: {user.email}'
            print(log)
        return render_template('reset_password_sended.html')
    return render_template('reset_password.html', form=form)

@bp.route('/set_new_password', methods=['GET', 'POST'])
def set_new_password():
    pass
    # token_raw = request.args.get('token') Nie pasuje jednak ale zsotawam b o może się przyda
    # username = request.args.get('username')
    
    # form = ChangePasswordForm() 

    # if not token_raw or not username:
    #     return redirect(url_for('bp.login'))

    # user = db.session.scalar(db.select(User).where(User.username == username))
    # if not user:
    #     return redirect(url_for('bp.login'))

    # reset_record = db.session.scalar(
    #     db.select(ResetPassword)
    #     .where(ResetPassword.user_id == user.id)
    #     .order_by(ResetPassword.id.desc())
    # )

    # valid_token = False
    # if reset_record:
    #     try:
    #         if argon2.verify(token_raw, reset_record.token_hash):
    #             valid_token = True
    #     except:
    #         pass
    
    # if reset_record.expires_at < datetime.now():
    #     valid_token=False

    # if reset_record.used:
    #     valid_token=False

    # if not valid_token:
    #     return redirect(url_for('auth.reset_password'))

    # if form.validate_on_submit():
    #     user.set_password(form.password_verifier.data)
        
    #     reset_record.used=True
    #     db.session.commit()

    #     return redirect(url_for('bp.login'))

    # return render_template('set_new_password.html', form=form)