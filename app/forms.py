from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, HiddenField, MultipleFileField
from wtforms.validators import DataRequired, Email, Length, ValidationError, Regexp, EqualTo
from app.db import db, User

class LoginForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired()], filters=[lambda x: x.lower() if x else None])
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
    ], filters=[lambda x: x.lower() if x else None])
    email = StringField('Email', validators=[DataRequired(), Email()])
    
    website = StringField('Website')

    password_verifier = HiddenField('PasswordVerifier', validators=[DataRequired()])
    password_salt = HiddenField('PasswordSalt', validators=[DataRequired()])

    public_key = HiddenField('PublicKey', validators=[DataRequired()])
    encrypted_private_key = HiddenField('EncPrivateKey', validators=[DataRequired()])
    private_key_iv = HiddenField('PrivateKeyIV', validators=[DataRequired()])

    signing_public_key = HiddenField('SigningPublicKey', validators=[DataRequired()])
    encrypted_signing_private_key = HiddenField('EncSigningPrivateKey', validators=[DataRequired()])
    signing_private_key_iv = HiddenField('SigningPrivateKeyIV', validators=[DataRequired()])

    submit = SubmitField('Register')

    def validate_username(self, username):
        username_data = username.data
        
        reserved_words = ['admin', 'administrator', 'root', 'support', 'help', 'api', 'bot', 'system']
        
        if username_data in reserved_words:
            raise ValidationError('This username is reserved used by system.')

        user = db.session.scalar(db.select(User).where(User.username == username_data))
        if user is not None:
            raise ValidationError('Login is used.')

    def validate_email(self, email):
        user = db.session.scalar(db.select(User).where(User.email == email.data))
        if user is not None:
            raise ValidationError('Email is used.')


class SendMessageForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()], filters=[lambda x: x.lower() if x else None])
    subject_encrypted = HiddenField('Subject', validators=[DataRequired()])
    content_encrypted = HiddenField('Content', validators=[DataRequired()])
    
    ephemeral_public_key = HiddenField('EphemeralPublicKey', validators=[DataRequired()])
    sender_encrypted_aes_key = HiddenField('SenderEncryptedAESKey', validators=[DataRequired()])
    recipient_encrypted_aes_key = HiddenField('RecipientEncryptedAESKey', validators=[DataRequired()])
    
    signature = HiddenField('Signature', validators=[DataRequired()])

    attachment_blob = MultipleFileField('Attachment')
    attachments_metadata_json = HiddenField('AttachmentsMetadataJSON')

    submit = SubmitField('Send')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password_verifier = HiddenField('PasswordVerifier', validators=[DataRequired()])
    password_salt = HiddenField('PasswordSalt', validators=[DataRequired()])

    public_key = HiddenField('PublicKey', validators=[DataRequired()])
    encrypted_private_key = HiddenField('EncPrivateKey', validators=[DataRequired()])
    private_key_iv = HiddenField('PrivateKeyIV', validators=[DataRequired()])

    signing_public_key = HiddenField('SigningPublicKey', validators=[DataRequired()])
    encrypted_signing_private_key = HiddenField('EncSigningPrivateKey', validators=[DataRequired()])
    signing_private_key_iv = HiddenField('SigningPrivateKeyIV', validators=[DataRequired()])

    submit = SubmitField('Change Password')

class ChangePasswordForm(FlaskForm):
    password_verifier = HiddenField('PasswordVerifier', validators=[DataRequired()])
    password_salt = HiddenField('PasswordSalt', validators=[DataRequired()])

    encrypted_private_key = HiddenField('EncPrivateKey', validators=[DataRequired()])
    private_key_iv = HiddenField('PrivateKeyIV', validators=[DataRequired()])

    encrypted_signing_private_key = HiddenField('EncSigningPrivateKey', validators=[DataRequired()])
    signing_private_key_iv = HiddenField('SigningPrivateKeyIV', validators=[DataRequired()])

    submit = SubmitField('Change Password')