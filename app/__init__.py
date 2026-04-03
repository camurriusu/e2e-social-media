from flask import Flask

from .db import db
from .routes import api
from .views import views


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="change-me-before-production",
        JSON_SORT_KEYS=False,
        SQLALCHEMY_DATABASE_URI="sqlite:///app.db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)

    with app.app_context():
        from . import models
        db.create_all()

    app.register_blueprint(api, url_prefix="/api")
    app.register_blueprint(views)

    return app

