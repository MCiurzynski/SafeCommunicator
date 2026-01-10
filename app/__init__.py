from flask import Flask, Request
from app.config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_login import LoginManager

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "600 per hour"], 
    storage_uri="memory://"
)

login_manager = LoginManager()



def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    # talisman = Talisman(app)
    limiter.init_app(app)
    
    login_manager.init_app(app)
    login_manager.session_protection = "strong"


    from app import routes
    app.register_blueprint(routes.bp)

    from app import auth
    app.register_blueprint(auth.bp)

    from app import api
    app.register_blueprint(api.bp)

    from app.db import init_app
    init_app(app)

    return app
