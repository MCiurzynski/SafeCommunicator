from flask import Flask
from app.config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "600 per hour"]
)

login_manager = LoginManager()

csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\''],
    'connect-src': ['\'self\''],
    'style-src': ['\'self\''],
    'img-src': ['\'self\'', 'data:']
}

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    talisman = Talisman(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'], 
        force_https=True
    )
    
    limiter.init_app(app)
    
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    login_manager.login_view = 'auth.login'

    from app.db import init_app
    init_app(app)

    from app import routes
    app.register_blueprint(routes.bp)

    from app import auth
    app.register_blueprint(auth.bp)

    from app import api
    app.register_blueprint(api.bp)

    return app