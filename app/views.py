from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from .db import db
from .models import User

views = Blueprint("views", __name__)


def _current_user() -> User | None:
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return db.session.get(User, user_id)


def _login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("views.login"))
        return f(*args, **kwargs)

    return decorated


@views.get("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("views.wall"))
    return redirect(url_for("views.login"))


@views.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("views.wall"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user.id
        return redirect(url_for("views.wall"))

    return render_template("login.html")


@views.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("views.wall"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username:
            flash("Username is required.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("register.html")

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session.clear()
        session["user_id"] = user.id
        return redirect(url_for("views.wall"))

    return render_template("register.html")


@views.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("views.login"))


@views.get("/wall")
@_login_required
def wall():
    user = _current_user()
    return render_template("wall.html", username=user.username)
