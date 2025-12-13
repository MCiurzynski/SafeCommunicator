from flask import current_app
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa
import sqlalchemy.orm as so
from typing import List, Optional
import click
from passlib.hash import argon2

class Base(so.DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class User(Base):
    __tablename__ = 'user'

    id: so.Mapped[int] = so.mapped_column(primary_key=True, autoincrement=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), unique=True, nullable=False)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), unique=True, nullable=False)
    password_hash: so.Mapped[str] = so.mapped_column(sa.String(256))
    public_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)
    encrypted_private_key: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)

    def check_password(self, password):
        return argon2.verify(password, self.password_hash)

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
