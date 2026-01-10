from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, jsonify, current_app
from app.forms import LoginForm, RegisterForm
from app.db import db, User
from flask_login import current_user, login_user, logout_user, login_required
import pyotp
import qrcode
import io
from app import limiter
import base64


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
            
        )
        
        user.totp_secret = new_totp_secret
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