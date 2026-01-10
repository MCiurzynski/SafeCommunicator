from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, HiddenField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp
from app.db import db, User

class LoginForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired()])
    password_verifier = HiddenField('PasswordVerifier', validators=[DataRequired()])
    
    totp_code = StringField('2FA Code', validators=[
        DataRequired(), Length(min=6, max=7, message="Code contains only 6 digits")
    ])
    
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Login', validators=[
        DataRequired(), 
        Length(min=3, max=64),
        Regexp(r'^[a-zA-Z0-9_-]+$', message="Login can contain only letters, digits, _ and -")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    
    website = StringField('Website')

    password_verifier = HiddenField('PasswordVerifier', validators=[DataRequired()])

    public_key = HiddenField('PublicKey', validators=[DataRequired()])
    encrypted_private_key = HiddenField('EncPrivateKey', validators=[DataRequired()])
    private_key_iv = HiddenField('PrivateKeyIV', validators=[DataRequired()])

    signing_public_key = HiddenField('SigningPublicKey', validators=[DataRequired()])
    encrypted_signing_private_key = HiddenField('EncSigningPrivateKey', validators=[DataRequired()])
    signing_private_key_iv = HiddenField('SigningPrivateKeyIV', validators=[DataRequired()])

    submit = SubmitField('Register')

    def validate_username(self, username):
        user = db.session.scalar(db.select(User).where(User.username == username.data))
        if user is not None:
            raise ValidationError('Login jest zajęty.')

    def validate_email(self, email):
        user = db.session.scalar(db.select(User).where(User.email == email.data))
        if user is not None:
            raise ValidationError('Email jest zajęty.')


class SendMessageForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    subject_encrypted = HiddenField('Subject', validators=[DataRequired()])
    content_encrypted = HiddenField('Content', validators=[DataRequired()])
    
    subject_nonce = HiddenField('SubjectNonce', validators=[DataRequired()])
    content_nonce = HiddenField('ContentNonce', validators=[DataRequired()])
    
    ephemeral_public_key = HiddenField('EphemeralPublicKey', validators=[DataRequired()])
    
    signature = HiddenField('Signature', validators=[DataRequired()])

    attachment_blob = FileField('Attachment')
    attachment_nonce = HiddenField('AttNonce')
    attachment_filename = HiddenField('AttFilename')
    attachment_filename_nonce = HiddenField('AttFilenameNonce')
    attachment_mime = HiddenField('AttMime')
    attachment_mime_nonce = HiddenField('AttMimeNonce')

    submit = SubmitField('Send')