from flask import Blueprint, render_template, redirect
from flask_login import login_required
from app.forms import SendMessageForm

bp = Blueprint('index', __name__, url_prefix='/')

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    return render_template('index.html')

@bp.route('/send', methods=['GET', 'POST'])
@login_required
def send():
    form = SendMessageForm()
    # if form.validate_on_submit():

    return render_template('send.html', form=form)