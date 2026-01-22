from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from app.forms import LoginForm, RegisterForm, ForgotPasswordForm, ResetPasswordForm, ChangePasswordForm
from app.db import db, User
from flask_login import current_user, login_user, logout_user, login_required
import pyotp
import qrcode
import io
from app import limiter
import base64
from passlib.hash import argon2
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
import secrets


bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/login', methods=['POST', 'GET'])
@limiter.limit(lambda: "100 per minute" if request.method == "GET" else "5 per minute")
def login():
    error_msg = "Invalid username, password or 2FA"

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        
        user = db.session.scalar(
            db.select(User).where(User.username == form.username.data)
        )

        if user:
            password_valid = user.check_password(form.password_verifier.data)
        
            totp_secret = user.totp_secret
            if totp_secret:
                totp = pyotp.TOTP(totp_secret)
                totp_valid = totp.verify(form.totp_code.data, valid_window=1)
            else:
                totp_valid = False
            
            is_valid = password_valid and totp_valid

        else:
            argon2.verify('dummy', '$argon2id$v=19$m=65536,t=3,p=4$4RzDeE/J+T/HOIewFiLk3A$hrnvgHjxuvh3emqI6pDRyBaI59CyODMGmJlS8/WL6bY')
            fake_secret = pyotp.random_base32()
            totp = pyotp.TOTP(fake_secret)
            totp.verify(form.totp_code.data, valid_window=1)
            
            is_valid = False

        
        if not is_valid:
            flash(error_msg, 'error')
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
        flash(error_msg, 'error')
        return jsonify({'success': False, 'message': 'Invalid request'}), 400

    return render_template('login.html', form=form)


@bp.route('/register', methods=['POST', 'GET'])
@limiter.limit(lambda: "100 per minute" if request.method == "GET" else "10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        if form.website.data:
            current_app.logger.warning(f"BOT DETECTED: {request.remote_addr}.")
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
            
            password_salt=form.password_salt.data
        )
        
        user.totp_secret = new_totp_secret
        user.set_password(form.password_verifier.data)

        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            flash('Username taken')
            return render_template('register.html', form=form)

        login_user(user)
        return redirect(url_for('auth.setup_2fa'))

    return render_template('register.html', form=form)


@bp.route('/setup-2fa')
@login_required
@limiter.limit("100 per hour")
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
@limiter.limit("5 per minute")
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/regenerate_2fa')
@login_required
@limiter.limit("5 per minute")
def regenerate_2fa():
    user = current_user
    new_totp_secret = pyotp.random_base32()
    user.totp_secret = new_totp_secret
    db.session.commit()
    return redirect(url_for('auth.setup_2fa'))

@bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.scalar(db.select(User).where(User.email == email))
        
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.now() + timedelta(minutes=15)
            db.session.commit()
            
            reset_link = url_for('auth.reset_password_confirm', token=token, _external=True)
            current_app.logger.warning(f"\n[EMAIL DEBUG] Reset Link for {email}: {reset_link}\n")
        flash('If the email address you provided exists in our database, we have sent you reset instructions..', 'info')
        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html', form=form)


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def reset_password_confirm(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    user = db.session.scalar(db.select(User).where(User.reset_token == token))
    
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.now():
        flash('Reset link is invalid.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        user.set_password(form.password_verifier.data)
        user.password_salt = form.password_salt.data
        
        user.public_key = form.public_key.data
        user.encrypted_private_key = form.encrypted_private_key.data
        user.private_key_iv = form.private_key_iv.data
        
        user.signing_public_key = form.signing_public_key.data
        user.encrypted_signing_private_key = form.encrypted_signing_private_key.data
        user.signing_private_key_iv = form.signing_private_key_iv.data
        
        user.reset_token = None
        user.reset_token_expiry = None
        
        db.session.commit()
        flash('Password is changed.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', form=form, token=token)

@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per hour")
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        current_user.set_password(form.password_verifier.data)
        current_user.password_salt = form.password_salt.data
        
        current_user.encrypted_private_key = form.encrypted_private_key.data
        current_user.private_key_iv = form.private_key_iv.data
        
        current_user.encrypted_signing_private_key = form.encrypted_signing_private_key.data
        current_user.signing_private_key_iv = form.signing_private_key_iv.data
        
        db.session.commit()
        flash('Password changed.', 'success')
        return redirect(url_for('main.index'))

    return render_template('change_password.html', form=form)