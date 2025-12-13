from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from app.db import db, User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=128, message='Length of username has to be between 4 and 128')])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password_first = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=256, message='Length of password has to be between 8 and 256')])
    password_second = PasswordField('Repeat password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = db.session.execute(db.select(User).where(User.username == username.data)).scalar()
        if user:
            raise ValidationError('This username is used')

    def validate_email(self, email):
        user = db.session.execute(db.select(User).where(User.email == email.data)).scalar()
        if user:
            raise ValidationError('This email is used')

    def validate_passwords(self, password_first, password_second):
        if password_first != password_first:
            raise ValidationError('Passwords are not the same')
        