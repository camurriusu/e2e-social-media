import json
from functools import wraps

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, flash, redirect, render_template, request, session, url_for, current_app

from .crypto import generate_keypair, encrypt_private_key, decrypt_private_key, encrypt_post, encrypt_symmetric_key, \
    decrypt_symmetric_key, decrypt_post, verify_cert
from .db import db
from .models import Group, Post, User, PostKey

views = Blueprint("views", __name__)


def _current_user() -> User | None:
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return db.session.get(User, user_id)


def _login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("views.login"))
        return f(*args, **kwargs)
    return decorated


def _make_solo_group(user: User) -> None:
    """Create a new group containing only this user."""
    group = Group()
    db.session.add(group)
    db.session.flush()
    user.group_id = group.id


def _cleanup_group(group: Group) -> None:
    """Delete a group if it has no members."""
    if not group.members:
        db.session.delete(group)


def _load_private_key():
    pem = session.get("private_key_pem")
    if not pem:
        return None
    return serialization.load_pem_private_key(pem.encode(), password=None)


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

        # Decrypt encrypted private key and save it in PEM format
        keypair = decrypt_private_key(user.private_key, user.salt, password)
        session["private_key_pem"] = keypair.private_bytes(serialization.Encoding.PEM,
                                                           serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()).decode()
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

        # Create the user's solo group first, then the user
        group = Group()
        db.session.add(group)
        db.session.flush()

        user = User(username=username, group_id=group.id)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        keypair, cert = generate_keypair(username, current_app.config["CA_CERT"], current_app.config["CA_KEY"])
        private_key, salt = encrypt_private_key(keypair, password)

        user.certificate = cert.public_bytes(serialization.Encoding.PEM).decode()
        user.private_key = private_key
        user.salt = salt
        db.session.commit()

        session.clear()
        session["user_id"] = user.id
        # Save private key in PEM format
        session["private_key_pem"] = keypair.private_bytes(serialization.Encoding.PEM,
                                                           serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()).decode()
        return redirect(url_for("views.wall"))

    return render_template("register.html")


@views.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("views.login"))


@views.route("/wall", methods=["GET", "POST"])
@_login_required
def wall():
    user = _current_user()
    if user is None:
        session.clear()
        return redirect(url_for("views.login"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content and len(content) <= 280:
            ciphertext, aes_key = encrypt_post(content)
            post = Post(user_id=user.id, content=ciphertext)
            db.session.add(post)
            # Flush to get post id
            db.session.flush()
            # For every member in the same group
            for member in User.query.filter_by(group_id=user.group_id).all():
                if member.certificate and verify_cert(member.certificate, current_app.config["CA_CERT"]):
                    # Encrypt post AES key with member's public key
                    public_key = x509.load_pem_x509_certificate(member.certificate.encode()).public_key()
                    encrypted_key = encrypt_symmetric_key(aes_key, public_key)
                    # A record for each member in the group is created, each with a copy of the encrypted AES key
                    db.session.add(PostKey(post_id=post.id, user_id=member.id, key=encrypted_key))
            db.session.commit()
        return redirect(url_for("views.wall"))

    posts = Post.query.order_by(Post.created_at.desc()).all()

    private_key = _load_private_key()
    if private_key is None:
        return redirect(url_for("views.logout"))
    # Make map {post id: encrypted aes key} of posts that this user can read
    post_keys = {postkey.post_id: postkey.key for postkey in PostKey.query.filter_by(user_id=user.id).all()}

    # List of (post, post_content) to pass decrypted content to template
    # without modifying post object in db
    new_posts = []
    # Iterate over all posts
    # Decrypt posts with post_id in post_keys using private key
    for post in posts:
        if post.id in post_keys:
            aes_key = decrypt_symmetric_key(post_keys[post.id], private_key)
            decrypted_content = decrypt_post(post.content, aes_key)
            new_posts.append((post, decrypted_content))
        else:
            new_posts.append((post, post.content))

    members = User.query.filter_by(group_id=user.group_id).order_by(User.username).all()
    members_json = json.dumps([{"id": m.id, "username": m.username} for m in members])
    return render_template("wall.html", username=user.username, posts=new_posts,
                           members_json=members_json, current_user_id=user.id)


@views.post("/group/add")
@_login_required
def group_add():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    user = _current_user()
    # target is the user to add
    target = User.query.filter_by(username=username).first()

    if not target:
        return {"error": "User not found"}, 404
    if target.group_id == user.group_id:
        return {"error": "Already in group"}, 409

    # Can't redirect since this endpoint is called by fetch() and not by browser
    # 401 redirects to login page in wall.js anyway
    private_key = _load_private_key()
    if private_key is None:
        return {"error": "Session expired"}, 401

    old_group = target.group
    target.group_id = user.group_id
    _cleanup_group(old_group)

    # Target loses access to all posts from old group
    PostKey.query.filter_by(user_id=target.id).delete()

    if not target.certificate or not verify_cert(target.certificate, current_app.config["CA_CERT"]):
        return {"error": "Invalid certificate"}, 400
    target_public_key = x509.load_pem_x509_certificate(target.certificate.encode()).public_key()

    # Copy every PostKey the user holds to the target user
    for postkey in PostKey.query.filter_by(user_id=user.id).all():
        # Get AES key inside postkey
        aes_key = decrypt_symmetric_key(postkey.key, private_key)
        # Encrypt it using target's public key so that they can decrypt it to read the post
        encrypted_key = encrypt_symmetric_key(aes_key, target_public_key)
        db.session.add(PostKey(post_id=postkey.post_id, user_id=target.id, key=encrypted_key))

    db.session.commit()
    return {"id": target.id, "username": target.username}


@views.post("/group/remove/<int:user_id>")
@_login_required
def group_remove(user_id):
    current = _current_user()
    # target is the user to remove
    target = db.session.get(User, user_id)

    if not target or target.group_id != current.group_id:
        return {"error": "Not in your group"}, 404

    group = current.group
    if len(group.members) == 1:
        return {"error": "Cannot remove yourself — you are the only member"}, 400

    # Delete all PostKeys belonging to target so they cannot read their old group's posts anymore
    PostKey.query.filter_by(user_id=target.id).delete()

    _make_solo_group(target)
    db.session.commit()

    return {"ok": True}
