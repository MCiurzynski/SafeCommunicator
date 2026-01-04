from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app.db import db, User, Message, Attachment
from app.forms import SendMessageForm
from datetime import datetime, timezone
import json
import base64

bp = Blueprint('main', __name__)

@bp.route('/')
@login_required
def index():
    messages = db.session.scalars(
        db.select(Message)
        .where(Message.recipient_id == current_user.id)
        .order_by(Message.created_at.desc())
    ).all()
    return render_template('index.html', messages=messages)

@bp.route('/send', methods=['GET', 'POST'])
@login_required
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
            iv=form.iv.data,
            
            ephemeral_public_key=form.ephemeral_public_key.data,
            signature=form.signature.data
        )
        
        db.session.add(msg)
        
        
        db.session.commit()
        

        return redirect(url_for('main.index'))

    return render_template('send.html', form=form)

@bp.route('/message/<int:message_id>')
@login_required
def view_message(message_id):
    msg = db.session.get(Message, message_id)
    
    if not msg or msg.recipient_id != current_user.id:
        flash('Brak dostępu.')
        return redirect(url_for('main.index'))
    
    if not msg.is_read:
        msg.is_read = True
        db.session.commit()

    return render_template('view.html', msg=msg)

@bp.route('/message/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = db.session.get(Message, message_id)
    
    if not msg or msg.recipient_id != current_user.id:
        flash('Nie masz uprawnień.')
        return redirect(url_for('main.index'))
    
    db.session.delete(msg)
    db.session.commit()
    
    flash('Usunięto wiadomość.')
    return redirect(url_for('main.index'))