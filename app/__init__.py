from flask import Flask
from app.config import Config

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)

    from app import routes
    app.register_blueprint(routes.bp)

    from app import auth
    app.register_blueprint(auth.bp)

    from app.db import init_app
    init_app(app)

    return app