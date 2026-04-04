from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .db import db


class Group(db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    members = db.relationship("User", back_populates="group")


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    author = db.relationship("User", backref="posts")


class PostKey(db.Model):
    __tablename__ = "post_keys"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), ondelete="CASCADE", nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), ondelete="CASCADE", nullable=False)
    key = db.Column(db.Text, nullable=False)

    __table_args__ = (db.UniqueConstraint("post_id", "user_id"))

    post = db.relationship("Post", backref=db.backref("keys", cascade="all, delete-orphan"))
    user = db.relationship("User")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    certificate = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    salt = db.Column(db.String(32), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey("groups.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    group = db.relationship("Group", back_populates="members")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict[str, str | int]:
        return {
            "id": self.id,
            "username": self.username,
            "created_at": self.created_at.isoformat(),
        }
