from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from app.db import db, User, Message, Attachment
from app.forms import SendMessageForm
import json
from app import limiter
import os
import uuid

bp = Blueprint('main', __name__)

@bp.route('/')
@login_required
@limiter.limit('10 per minute')
def index():
    messages = db.session.scalars(
        db.select(Message)
        .where(Message.recipient_id == current_user.id)
        .order_by(Message.created_at.desc())
    ).all()
    return render_template('index.html', messages=messages)

@bp.route('/send', methods=['GET', 'POST'])
@login_required
@limiter.limit(lambda: "50 per minute" if request.method == "GET" else "10 per minute")
def send_message():
    form = SendMessageForm()
    if form.validate_on_submit():
        recipient = db.session.scalar(
            db.select(User).where(User.username == form.recipient.data)
        )
        
        msg = Message(
            sender=current_user,
            recipient=recipient,
            
            encrypted_subject=form.subject_encrypted.data,
            encrypted_content=form.content_encrypted.data,
            
            ephemeral_public_key=form.ephemeral_public_key.data,
            signature=form.signature.data
        )
        
        db.session.add(msg)
        db.session.flush()
        files = request.files.getlist('attachment_blob')
        metadata_json = request.form.get('attachments_metadata_json')
        if metadata_json and files:
            metadata_list = json.loads(metadata_json)
            if len(files) > 10:
                return jsonify({"error": f"You can send max 10 files."}), 400
            if len(files) == len(metadata_list):
                for i, file_storage in enumerate(files):
                    meta = metadata_list[i]
                
                storage_filename = f"{uuid.uuid4().hex}.enc"
                
                save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], storage_filename)
                
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                file_storage.save(save_path)
                
                file_size = os.path.getsize(save_path)

                attachment = Attachment(
                    message=msg,
                    encrypted_filename=meta['encrypted_filename'],
                    encrypted_mime_type=meta['encrypted_mime'],
                    file_path=storage_filename,
                    file_size=file_size
                )
                db.session.add(attachment)

        db.session.commit()
        

        return redirect(url_for('main.index'))

    return render_template('send.html', form=form)

@bp.route('/message/<int:message_id>')
@login_required
@limiter.limit('20 per minute')
def view_message(message_id):
    msg = db.session.get(Message, message_id)
    
    if not msg or msg.recipient_id != current_user.id:
        return redirect(url_for('main.index'))
    
    if not msg.is_read:
        msg.is_read = True
        db.session.commit()

    return render_template('view.html', msg=msg)

@bp.route('/message/<int:message_id>/delete', methods=['POST'])
@login_required
@limiter.limit('20 per minute')
def delete_message(message_id):
    msg = db.session.get(Message, message_id)
    
    if not msg or msg.recipient_id != current_user.id:
        flash('Invalid.')
        return redirect(url_for('main.index'))
    
    for attachment in msg.attachments:
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], attachment.file_path)
        try:
            if os.path.exists(full_path):
                os.remove(full_path)
        except OSError as e:
            current_app.logger.error(f"Error deleting file {full_path}: {e}")

    db.session.delete(msg)
    db.session.commit()
    
    flash('Message deleted.')
    return redirect(url_for('main.index'))