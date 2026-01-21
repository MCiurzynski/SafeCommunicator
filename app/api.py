from flask import Blueprint, jsonify, send_file, current_app
from flask_login import login_required, current_user
from app.db import db, User, Message, Attachment
from app import limiter
from io import BytesIO
import hmac
import hashlib
import base64

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/get_public_key/<username>')
@login_required
@limiter.limit('10 per minute')
def get_public_key(username):
    username = username.lower()
    user = db.session.scalar(db.select(User).where(User.username == username))
    if user:
        return jsonify({
            'public_key': user.public_key,
            'signing_public_key': user.signing_public_key
        })
    return jsonify({'error': 'User not found'}), 404

@bp.route('/attachment/<int:attachment_id>')
@login_required
@limiter.limit('100 per minute')
def get_attachment(attachment_id):
    att = db.session.get(Attachment, attachment_id)

    if not att:
        return jsonify({'error': 'Attachment not found'}), 404

    if (
        att.message.recipient_id != current_user.id and
        att.message.sender_id != current_user.id
    ):
        return jsonify({'error': 'Access denied'}), 403

    raw_data = att.encrypted_data

    if not isinstance(raw_data, (bytes, bytearray)):
        return jsonify({'error': 'Invalid attachment data'}), 500

    buffer = BytesIO(raw_data)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name='blob'
    )

@bp.route('/user/salt/<username>')
@limiter.limit('10 per minute')
def get_user_salt(username):
    username = username.lower()
    user = db.session.scalar(db.select(User).where(User.username == username))
    
    if user:
        return jsonify({
            'password_salt': user.password_salt
        })
    
    secret_key = current_app.config['SECRET_KEY'].encode('utf-8')
    
    h = hmac.new(secret_key, username.encode('utf-8'), hashlib.sha256)
    
    fake_salt_bytes = h.digest()[:16] 

    fake_salt_b64 = base64.b64encode(fake_salt_bytes).decode('utf-8')

    return jsonify({
        'password_salt': fake_salt_b64
    })

@bp.route('/me')
@login_required
def get_me():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username
    })