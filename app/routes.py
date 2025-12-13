from flask import Blueprint

bp = Blueprint('index', __name__, url_prefix='/')

@bp.route('/')
@bp.route('/index')
def index():
    return "Hello, World!"