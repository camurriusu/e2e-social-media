from datetime import datetime, timezone

from .db import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, str | int]:
        return {
            "id": self.id,
            "username": self.username,
            "bio": self.bio or "",
            "created_at": self.created_at.isoformat(),
        }

