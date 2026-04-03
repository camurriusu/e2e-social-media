from http import HTTPStatus

from flask import Blueprint, request

from .db import db
from .models import User

api = Blueprint("api", __name__)


@api.get("/health")
def health() -> tuple[dict[str, str], int]:
    return {"status": "ok"}, HTTPStatus.OK


@api.get("/users")
def list_users() -> tuple[dict[str, list[dict[str, str | int]]], int]:
    users = User.query.order_by(User.id.asc()).all()
    return {"users": [user.to_dict() for user in users]}, HTTPStatus.OK


@api.get("/users/<int:item_id>")
def get_item(item_id: int):
    user = db.session.get(User, item_id)
    if user is None:
        return {"error": "user not found"}, HTTPStatus.NOT_FOUND
    return user.to_dict(), HTTPStatus.OK


@api.post("/users")
def create_item():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    if not username:
        return (
            {
                "error": "username is required",
            },
            HTTPStatus.BAD_REQUEST,
        )

    user = User(username=username)
    db.session.add(user)
    db.session.commit()

    return user.to_dict(), HTTPStatus.CREATED


