from flask import Flask

from .routes import api


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        JSON_SORT_KEYS=False,
    )

    if test_config:
        app.config.update(test_config)

    app.register_blueprint(api, url_prefix="/api")

    @app.get("/")
    def index() -> dict[str, str]:
        return {"message": "Flask is running"}

    return app

