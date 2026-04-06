from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask_session import Session

from .crypto import generate_ca, load_ca
from .db import db
from .views import views


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="change-me-before-production",
        JSON_SORT_KEYS=False,
        SQLALCHEMY_DATABASE_URI="sqlite:///app.db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TYPE="filesystem",
        SESSION_FILE_DIR=str(Path(__file__).parent.parent / "instance" / "flask_sessions"),
        SESSION_PERMANENT=False,
    )

    Session(app)
    db.init_app(app)

    with app.app_context():
        from . import models
        db.create_all()

    _init_ca(app)

    app.register_blueprint(views)

    return app


def _init_ca(app: Flask) -> None:
    # Create CA key and cert paths
    ca_dir = Path(app.config.get("CA_DIR", "ca"))
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "ca_key.pem"
    cert_path = ca_dir / "ca_cert.pem"

    # If key and cert exist, load
    if key_path.exists() and cert_path.exists():
        ca_key, ca_cert = load_ca(key_path, cert_path)
    # Else, generate new ones and save
    else:
        ca_key, ca_cert = generate_ca()
        # Encode key and cert as PEM
        private_key_pem = ca_key.private_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PrivateFormat.PKCS8,
                                               encryption_algorithm=serialization.NoEncryption()).decode()
        key_path.write_text(private_key_pem)
        cert_path.write_text(ca_cert.public_bytes(serialization.Encoding.PEM).decode())

    app.config["CA_KEY"] = ca_key
    app.config["CA_CERT"] = ca_cert