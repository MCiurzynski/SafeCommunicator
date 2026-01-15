from flask import Blueprint, jsonify, send_file, current_app
from flask_login import login_required, current_user
from app.db import db, User, Message, Attachment
from app import limiter
import os

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/get_public_key/<username>')
@login_required
@limiter.limit('10 per minute')
def get_public_key(username):
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

    if (att.message.recipient_id != current_user.id and 
        att.message.sender_id != current_user.id):
        return jsonify({'error': 'Access denied'}), 403

    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], att.file_path)

    if not os.path.exists(full_path):
        return jsonify({'error': 'File missing on server'}), 500

    return send_file(
        full_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name='blob'
    )

@bp.route('/user/salt/<username>')
@limiter.limit('10 per minute')
def get_user_salt(username):
    user = db.session.scalar(db.select(User).where(User.username == username))
    if user:
        return jsonify({
            'password_salt': user.password_salt
        })
    return jsonify({'error': 'User not found'}), 404