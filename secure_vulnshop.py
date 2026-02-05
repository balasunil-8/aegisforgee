import os
import time
import socket
import ipaddress
from datetime import timedelta
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)

# ============================================================
# VulnShop API (SECURE/FIXED VERSION)
# Run locally for teaching: "attack -> patch -> re-test".
# ============================================================

app = Flask(__name__)

# --- Secure defaults (API8) ---
app.config["DEBUG"] = False
app.config["JSON_SORT_KEYS"] = False

# Strong secret required (API2)
# Set:  set JWT_SECRET_KEY=some-long-random-string
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "")
if not app.config["JWT_SECRET_KEY"] or len(app.config["JWT_SECRET_KEY"]) < 16:
    # Safe fallback for LOCAL demo only; still recommend env var.
    app.config["JWT_SECRET_KEY"] = "CHANGE_ME_USE_A_LONG_RANDOM_SECRET"

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///vulnshop_secure.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CORS restricted (API8): allow only your classroom origin(s) or keep local only
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost").split(",")
CORS(app, resources={r"/api/*": {"origins": [o.strip() for o in ALLOWED_ORIGINS if o.strip()]}})

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ------------------------------
# Simple in-memory rate limiter (API2/API4)
# (good enough for classroom; real apps use Redis/Gateway/WAF)
# ------------------------------
RATE_WINDOW_SEC = 60
MAX_LOGIN_ATTEMPTS_PER_IP = 10
_login_attempts = {}  # ip -> [(ts), ...]


def _client_ip() -> str:
    # In real deployments consider reverse-proxy headers carefully.
    return request.remote_addr or "unknown"


def _rate_limit_login() -> bool:
    ip = _client_ip()
    now = time.time()
    arr = _login_attempts.get(ip, [])
    arr = [t for t in arr if now - t < RATE_WINDOW_SEC]
    if len(arr) >= MAX_LOGIN_ATTEMPTS_PER_IP:
        _login_attempts[ip] = arr
        return False
    arr.append(now)
    _login_attempts[ip] = arr
    return True


# ============================================================
# Models
# ============================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    name = db.Column(db.String(120), default="")
    role = db.Column(db.String(50), default="user")  # user/admin
    balance = db.Column(db.Integer, default=1000)  # cents (demo)

    def to_public(self):
        # No sensitive fields (API3)
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "balance": self.balance,
        }


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    price = db.Column(db.Integer, nullable=False)  # cents
    stock = db.Column(db.Integer, default=10)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "price": self.price, "stock": self.stock}


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=1)

    total_price = db.Column(db.Integer, default=0)  # computed server-side
    status = db.Column(db.String(50), default="CREATED")  # CREATED, PAID, CONFIRMED
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "total_price": self.total_price,
            "status": self.status,
            "created_at": self.created_at,
        }


# ============================================================
# Helpers
# ============================================================

def seed_data():
    db.create_all()

    if not User.query.first():
        u1 = User(email="user1@example.com", password_hash=generate_password_hash("Password123"), name="User One", role="user", balance=1000)
        u2 = User(email="user2@example.com", password_hash=generate_password_hash("Password123"), name="User Two", role="user", balance=500)
        admin = User(email="admin@example.com", password_hash=generate_password_hash("Admin123"), name="Admin", role="admin", balance=999999)
        db.session.add_all([u1, u2, admin])

    if not Product.query.first():
        db.session.add_all([
            Product(name="Laptop", price=120000, stock=5),
            Product(name="Headphones", price=5000, stock=25),
            Product(name="Phone", price=80000, stock=10),
        ])

    db.session.commit()

    if not Order.query.first():
        # Create one order per user (owned properly)
        o1 = Order(user_id=1, product_id=1, quantity=1, total_price=120000, status="CREATED")
        o2 = Order(user_id=2, product_id=2, quantity=2, total_price=10000, status="CREATED")
        db.session.add_all([o1, o2])
        db.session.commit()


def current_user():
    uid = get_jwt_identity()
    try:
        uid = int(uid)
    except Exception:
        return None
    return User.query.get(uid)


def require_admin(user):
    if not user or user.role != "admin":
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    return None


def require_owner_or_admin(user, owner_id):
    if not user:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if user.role == "admin":
        return None
    if user.id != owner_id:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    return None


# ============================================================
# SSRF protections (API7)
# ============================================================

def is_private_or_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except Exception:
        return True


def resolve_host_ips(hostname: str):
    # Resolve DNS to IPs; block if any resolves to internal.
    ips = []
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            ips.append(ip)
    except Exception:
        pass
    return list(set(ips))


def validate_outbound_url(url: str):
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False, "Only http/https allowed"
        if not p.hostname:
            return False, "Invalid URL host"

        # Block common local hostnames
        if p.hostname.lower() in ("localhost",):
            return False, "Localhost blocked"

        ips = resolve_host_ips(p.hostname)
        if not ips:
            return False, "Could not resolve host"

        for ip in ips:
            if is_private_or_local_ip(ip):
                return False, f"Blocked internal/private IP resolution: {ip}"

        # Block cloud metadata IP even if passed directly
        if p.hostname == "169.254.169.254":
            return False, "Metadata IP blocked"

        return True, "OK"
    except Exception:
        return False, "Invalid URL"


# ============================================================
# Health & Setup
# ============================================================

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "VulnShop API (Secure)", "time": int(time.time())})


@app.post("/api/setup/reset")
def reset_db():
    """
    For classroom convenience only.
    In real apps: never expose this.
    """
    if os.getenv("ALLOW_RESET", "true").lower() != "true":
        return jsonify({"ok": False, "error": "Reset disabled"}), 403
    db.drop_all()
    db.create_all()
    seed_data()
    return jsonify({"ok": True, "message": "Secure DB reset & seeded."})


# ============================================================
# AUTH (API2 fixed)
# - hashed passwords
# - basic rate limiting
# ============================================================

@app.post("/api/auth/login")
def login():
    if not _rate_limit_login():
        return jsonify({"ok": False, "error": "Too many attempts, slow down"}), 429

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({"ok": True, "access_token": token, "user": user.to_public()})


# ============================================================
# USERS (API1 fixed + API3 fixed)
# - only owner or admin can read
# - PATCH allows only safe fields
# ============================================================

@app.get("/api/users/<int:user_id>")
@jwt_required()
def get_user(user_id):
    u = current_user()
    denial = require_owner_or_admin(u, user_id)
    if denial:
        return denial

    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    return jsonify({"ok": True, "user": user.to_public()})


@app.patch("/api/users/<int:user_id>")
@jwt_required()
def patch_user(user_id):
    u = current_user()
    denial = require_owner_or_admin(u, user_id)
    if denial:
        return denial

    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    payload = request.get_json(silent=True) or {}

    # Allowlist only safe fields (API3 fix)
    allowed = {"name", "email"}
    for k in list(payload.keys()):
        if k not in allowed:
            payload.pop(k, None)

    if "email" in payload:
        payload["email"] = str(payload["email"]).strip().lower()

    if "name" in payload:
        payload["name"] = str(payload["name"])[:120]

    for k, v in payload.items():
        setattr(user, k, v)

    db.session.commit()
    return jsonify({"ok": True, "user": user.to_public()})


# ============================================================
# PRODUCTS (API4 fixed + API5 fixed)
# - /api/products has pagination caps
# - delete product is admin only
# ============================================================

@app.get("/api/products")
def list_products():
    # API4 fix: enforce caps
    try:
        limit = int(request.args.get("limit", "10"))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        return jsonify({"ok": False, "error": "limit/offset must be integers"}), 400

    if limit < 1 or limit > 100:
        return jsonify({"ok": False, "error": "limit must be 1..100"}), 400
    if offset < 0 or offset > 10000:
        return jsonify({"ok": False, "error": "offset out of range"}), 400

    items = Product.query.offset(offset).limit(limit).all()
    return jsonify({"ok": True, "count": len(items), "products": [p.to_dict() for p in items]})


@app.delete("/api/products/<int:product_id>")
@jwt_required()
def delete_product(product_id):
    u = current_user()
    denial = require_admin(u)
    if denial:
        return denial

    p = Product.query.get(product_id)
    if not p:
        return jsonify({"ok": False, "error": "Product not found"}), 404
    db.session.delete(p)
    db.session.commit()
    return jsonify({"ok": True, "deleted_product_id": product_id})


# ============================================================
# ORDERS (API1 fixed + API6 fixed + API3 fixed)
# - price computed server-side
# - ownership checks
# - confirm requires PAID
# ============================================================

@app.post("/api/orders")
@jwt_required()
def create_order():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    try:
        product_id = int(data.get("product_id", 0))
        quantity = int(data.get("quantity", 1))
    except Exception:
        return jsonify({"ok": False, "error": "Invalid product_id/quantity"}), 400

    if quantity < 1 or quantity > 20:
        return jsonify({"ok": False, "error": "quantity must be 1..20"}), 400

    p = Product.query.get(product_id)
    if not p:
        return jsonify({"ok": False, "error": "Product not found"}), 404
    if p.stock < quantity:
        return jsonify({"ok": False, "error": "Insufficient stock"}), 409

    # API3 fix: compute server-side total; ignore client price completely
    total = p.price * quantity

    o = Order(user_id=u.id, product_id=product_id, quantity=quantity, total_price=total, status="CREATED")
    db.session.add(o)
    db.session.commit()
    return jsonify({"ok": True, "order": o.to_dict()})


@app.get("/api/orders/<int:order_id>")
@jwt_required()
def get_order(order_id):
    u = current_user()
    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    denial = require_owner_or_admin(u, o.user_id)
    if denial:
        return denial

    return jsonify({"ok": True, "order": o.to_dict()})


@app.post("/api/orders/<int:order_id>/pay")
@jwt_required()
def pay_order(order_id):
    u = current_user()
    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    denial = require_owner_or_admin(u, o.user_id)
    if denial:
        return denial

    if o.status != "CREATED":
        return jsonify({"ok": False, "error": "Order not payable"}), 409

    # Enforce payment business rules
    if u.balance < o.total_price:
        return jsonify({"ok": False, "error": "Insufficient balance"}), 402

    # Reduce stock & balance safely (demo)
    p = Product.query.get(o.product_id)
    if not p or p.stock < o.quantity:
        return jsonify({"ok": False, "error": "Stock changed, cannot pay"}), 409

    u.balance -= o.total_price
    p.stock -= o.quantity
    o.status = "PAID"
    db.session.commit()

    return jsonify({"ok": True, "order": o.to_dict(), "user_balance": u.balance})


@app.post("/api/orders/<int:order_id>/confirm")
@jwt_required()
def confirm_order(order_id):
    u = current_user()
    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    denial = require_owner_or_admin(u, o.user_id)
    if denial:
        return denial

    # API6 fix: enforce flow
    if o.status != "PAID":
        return jsonify({"ok": False, "error": "Order must be PAID before confirming"}), 409

    o.status = "CONFIRMED"
    db.session.commit()
    return jsonify({"ok": True, "order": o.to_dict()})


# ============================================================
# SSRF (API7 fixed)
# - blocks internal/private/localhost + requires http(s)
# ============================================================

@app.post("/api/utils/fetch-url")
@jwt_required()
def fetch_url():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"ok": False, "error": "url required"}), 400

    ok, reason = validate_outbound_url(url)
    if not ok:
        return jsonify({"ok": False, "error": f"Blocked: {reason}"}), 403

    try:
        r = requests.get(url, timeout=3, allow_redirects=False)
        return jsonify({
            "ok": True,
            "fetched_url": url,
            "status_code": r.status_code,
            "body_preview": r.text[:200],
        })
    except Exception:
        return jsonify({"ok": False, "error": "Fetch failed"}), 502


# ============================================================
# ADMIN (API5 fixed)
# ============================================================

@app.get("/api/admin/users")
@jwt_required()
def admin_list_users():
    u = current_user()
    denial = require_admin(u)
    if denial:
        return denial

    users = User.query.all()
    return jsonify({"ok": True, "users": [x.to_public() for x in users]})


# ============================================================
# API9 fixed: remove legacy debug endpoint
# (we intentionally DO NOT implement /api/v1/debug/users)
# If requested, Flask returns 404.
# ============================================================


# ============================================================
# API10 fixed: allowlist third-party APIs only
# ============================================================

PROVIDER_ALLOWLIST = [h.strip().lower() for h in os.getenv("PROVIDER_ALLOWLIST", "").split(",") if h.strip()]


@app.post("/api/shipping/quote")
@jwt_required()
def shipping_quote():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    provider_url = str(data.get("provider_url", "")).strip()
    order_id = data.get("order_id")

    try:
        order_id = int(order_id)
    except Exception:
        return jsonify({"ok": False, "error": "order_id must be int"}), 400

    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    # Ownership check (API1)
    denial = require_owner_or_admin(u, o.user_id)
    if denial:
        return denial

    if not provider_url:
        return jsonify({"ok": False, "error": "provider_url required"}), 400

    # Block unsafe consumption by allowlisting provider hostnames (API10)
    p = urlparse(provider_url)
    host = (p.hostname or "").lower()
    if not host or host not in PROVIDER_ALLOWLIST:
        return jsonify({"ok": False, "error": "Provider not allowed"}), 403

    # Also apply SSRF protections here
    ok, reason = validate_outbound_url(provider_url)
    if not ok:
        return jsonify({"ok": False, "error": f"Blocked: {reason}"}), 403

    try:
        resp = requests.get(provider_url, timeout=3, allow_redirects=False)
        if resp.status_code != 200:
            return jsonify({"ok": False, "error": "Provider error"}), 502
        payload = resp.json()

        # Validate schema strictly
        quote = payload.get("quote", None)
        if not isinstance(quote, int) or quote < 0 or quote > 1_000_000:
            return jsonify({"ok": False, "error": "Invalid quote"}), 502

        return jsonify({
            "ok": True,
            "order_id": order_id,
            "quote": quote,
            "provider_host": host
        })
    except Exception:
        return jsonify({"ok": False, "error": "Provider fetch failed"}), 502


# ============================================================
# Start
# ============================================================

if __name__ == "__main__":
    with app.app_context():
        seed_data()

    # Bind to LAN for classroom
    app.run(host="0.0.0.0", port=5000, debug=False)
