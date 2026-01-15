from flask import Blueprint, jsonify, send_file
from flask_login import login_required, current_user
from app.db import db, User, Message, Attachment
from app import limiter
from io import BytesIO

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