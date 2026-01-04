from flask import Blueprint, jsonify, redirect
from flask_login import login_required, current_user
from app.db import db, User, Message, Attachment
from app import limiter
import base64

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/get_public_key/<username>')
@login_required
@limiter.limit('50 per minute')
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
def get_attachment(attachment_id):
    att = db.session.get(Attachment, attachment_id)
    if not att:
        return jsonify({'error': 'Not found'}), 404
        
    if (att.message.recipient_id != current_user.id and att.message.sender_id != current_user.id):
        return jsonify({'error': 'Access denied'}), 403

    # Pobieramy dane z bazy (to są bytes)
    raw_data = att.encrypted_data
    
    # Jeśli to bajty (a są, bo masz LargeBinary), zamień na string Base64 dla JSON-a
    if isinstance(raw_data, bytes):
        data_as_string = base64.b64encode(raw_data).decode('utf-8')
    else:
        data_as_string = raw_data

    return jsonify({
        'filename': att.filename,
        'mime_type': att.mime_type,
        'encrypted_data': data_as_string, # Wysyłamy string Base64
        'iv': att.iv
    })

