from flask import current_app
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa
import sqlalchemy.orm as so
from typing import List, Optional
import click
from passlib.hash import argon2
from flask_login import UserMixin
from datetime import datetime, timezone
from app.utils import encrypt_totp_secret, decrypt_totp_secret

class Base(so.DeclarativeBase):
    pass

from app import login_manager as login
db = SQLAlchemy(model_class=Base)

class User(Base, UserMixin):
    __tablename__ = 'user'

    id: so.Mapped[int] = so.mapped_column(primary_key=True, autoincrement=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), unique=True, nullable=False)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), unique=True, nullable=False)
    
    password_hash: so.Mapped[str] = so.mapped_column(sa.String(256), nullable=False)
    password_salt: so.Mapped[str] = so.mapped_column(sa.String(64), nullable=False)

    encrypted_totp_secret: so.Mapped[Optional[str]] = so.mapped_column(sa.Text, nullable=False)
    
    public_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False) 
    encrypted_private_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False) 
    private_key_iv: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)

    signing_public_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False) 
    encrypted_signing_private_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)
    signing_private_key_iv: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)

    def set_password(self, password_verifier):
        self.password_hash = argon2.hash(password_verifier)

    def check_password(self, password_verifier):
        return argon2.verify(password_verifier, self.password_hash)
    
    @property
    def totp_secret(self):
        return decrypt_totp_secret(self.encrypted_totp_secret)
    
    @totp_secret.setter
    def totp_secret(self, totp_secret):
        self.encrypted_totp_secret = encrypt_totp_secret(totp_secret)
    
    sent_messages: so.Mapped[List["Message"]] = so.relationship(
        foreign_keys="Message.sender_id", back_populates="sender"
    )
    
    received_messages: so.Mapped[List["Message"]] = so.relationship(
        foreign_keys="Message.recipient_id", back_populates="recipient"
    )

class Message(Base):
    __tablename__ = 'message'

    id: so.Mapped[int] = so.mapped_column(primary_key=True, autoincrement=True)
    sender_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id'), nullable=False)
    recipient_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id'), nullable=False)

    encrypted_subject: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)
    encrypted_content: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)

    ephemeral_public_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)
    sender_encrypted_aes_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)
    recipient_encrypted_aes_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)

    signature: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)

    created_at: so.Mapped[datetime] = so.mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
    is_read: so.Mapped[bool] = so.mapped_column(default=False)
    
    sender: so.Mapped["User"] = so.relationship(foreign_keys=[sender_id], back_populates="sent_messages")
    recipient: so.Mapped["User"] = so.relationship(foreign_keys=[recipient_id], back_populates="received_messages")
    
    attachments: so.Mapped[List["Attachment"]] = so.relationship(
        back_populates="message", cascade="all, delete-orphan"
    )

class Attachment(Base):
    __tablename__ = 'attachment'

    id: so.Mapped[int] = so.mapped_column(primary_key=True, autoincrement=True)
    message_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('message.id'), nullable=False)

    encrypted_filename: so.Mapped[str] = so.mapped_column(sa.String(255), nullable=False)
    encrypted_mime_type: so.Mapped[str] = so.mapped_column(sa.String(128), nullable=False)
    file_size: so.Mapped[int] = so.mapped_column(sa.Integer, nullable=False)

    encrypted_data: so.Mapped[bytes] = so.mapped_column(sa.LargeBinary, nullable=False)

    message: so.Mapped["Message"] = so.relationship(back_populates="attachments")

def init_db():
    with current_app.app_context():
        db.drop_all()
        db.create_all()

@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables"""
    init_db()
    click.echo('Initialized the database')

def init_app(app):
    db.init_app(app)
    app.cli.add_command(init_db_command)
    login.init_app(app)
    login.login_view = 'auth.login'
    login.login_message = "Log in to get access."

@login.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))