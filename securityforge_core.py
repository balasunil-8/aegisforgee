import os
import time
import json
from datetime import timedelta
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from datetime import datetime

# ============================================================
# VulnShop API (INTENTIONALLY VULNERABLE)
# OWASP API Top 10 (2023) teaching lab
# Run locally only.
# ============================================================

app = Flask(__name__)

# --- Intentionally insecure configuration (API8: Security Misconfiguration) ---
app.config["DEBUG"] = True  # don't do this in real apps
app.config["JSON_SORT_KEYS"] = False

# Weak secrets + long expiry (API2: Broken Authentication)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret")  # weak default
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

# SQLite local DB
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///vulnshop.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CORS wide open (API8: Security Misconfiguration)
CORS(app, resources={r"/api/*": {"origins": "*"}})

db = SQLAlchemy(app)
jwt = JWTManager(app)


# ============================================================
# Models
# ============================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # INTENTIONALLY INSECURE: plaintext password (API2)
    password = db.Column(db.String(200), nullable=False)

    name = db.Column(db.String(120), default="")
    role = db.Column(db.String(50), default="user")  # "user" or "admin"
    is_admin = db.Column(db.Boolean, default=False)

    # For business logic demos
    balance = db.Column(db.Integer, default=1000)  # pretend currency in cents

    def to_dict(self):
        # INTENTIONALLY EXPOSES TOO MUCH (API3: Excessive Data Exposure / Property issues)
        return {
            "id": self.id,
            "email": self.email,
            "password": self.password,      # BAD: exposed
            "name": self.name,
            "role": self.role,
            "is_admin": self.is_admin,
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
    user_id = db.Column(db.Integer, nullable=False)   # ownership
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=1)

    # INTENTIONALLY INSECURE: price stored from client (API3 / Business logic)
    client_price = db.Column(db.Integer, default=0)

    status = db.Column(db.String(50), default="CREATED")  # CREATED, PAID, CONFIRMED
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "client_price": self.client_price,
            "status": self.status,
            "created_at": self.created_at,
        }


# ============================================================
# Exploit logging model (audit trail)
# ============================================================
class ExploitLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()))
    user_id = db.Column(db.Integer, nullable=True)
    event_type = db.Column(db.String(120), nullable=False)
    endpoint = db.Column(db.String(256), nullable=False)
    payload = db.Column(db.Text, nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    note = db.Column(db.String(512), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "endpoint": self.endpoint,
            "payload": self.payload,
            "ip": self.ip,
            "note": self.note,
        }


# ============================================================
# Helpers
# ============================================================

def seed_data():
    """Create tables and seed demo users/products/orders."""
    db.create_all()

    if not User.query.first():
        # More realistic set of users for richer lab scenarios
        demo_users = [
            User(email="alice.jones@example.com", password="AlicePass1!", name="Alice Jones", role="user", is_admin=False, balance=25000),
            User(email="bob.smith@example.com", password="BobPass2!", name="Bob Smith", role="user", is_admin=False, balance=15000),
            User(email="carol.wong@example.com", password="CarolPass3!", name="Carol Wong", role="user", is_admin=False, balance=8000),
            User(email="devteam@example.com", password="DevTeam$123", name="Dev Team", role="user", is_admin=False, balance=5000),
            User(email="ops@example.com", password="Ops$ecure", name="Operations", role="user", is_admin=False, balance=12000),
            User(email="manager@example.com", password="Manager!234", name="Manager", role="user", is_admin=False, balance=30000),
            User(email="auditor@example.com", password="Audit#2026", name="Auditor", role="user", is_admin=False, balance=4000),
            User(email="supplier@example.com", password="SupplyChain1", name="Supplier Co.", role="user", is_admin=False, balance=6000),
            User(email="support@example.com", password="SupportPass7", name="Support", role="user", is_admin=False, balance=2000),
            User(email="admin@example.com", password="Admin123", name="Administrator", role="admin", is_admin=True, balance=999999),
        ]
        db.session.add_all(demo_users)

    if not Product.query.first():
        demo_products = [
            Product(name="Laptop Pro 16", price=159999, stock=8),
            Product(name="Noise-Cancelling Headphones", price=19999, stock=40),
            Product(name="Flagship Phone X", price=99999, stock=15),
            Product(name="Wireless Charger", price=2999, stock=120),
            Product(name="USB-C Cable", price=999, stock=500),
            Product(name="Smartwatch Series 7", price=24999, stock=30),
            Product(name="Gaming Mouse", price=4999, stock=70),
            Product(name="4K Monitor", price=32999, stock=20),
            Product(name="Bluetooth Speaker", price=7999, stock=60),
            Product(name="External SSD 1TB", price=14999, stock=25),
        ]
        db.session.add_all(demo_products)

    db.session.commit()

    if not Order.query.first():
        # create a richer set of orders across multiple users and products
        demo_orders = [
            Order(user_id=1, product_id=1, quantity=1, client_price=159999, status="CREATED"),
            Order(user_id=2, product_id=2, quantity=1, client_price=19999, status="PAID"),
            Order(user_id=3, product_id=3, quantity=2, client_price=199998, status="CREATED"),
            Order(user_id=4, product_id=5, quantity=3, client_price=2997, status="CONFIRMED"),
            Order(user_id=5, product_id=6, quantity=1, client_price=24999, status="CREATED"),
            Order(user_id=6, product_id=4, quantity=10, client_price=29990, status="CREATED"),
            Order(user_id=7, product_id=10, quantity=1, client_price=14999, status="PAID"),
            Order(user_id=8, product_id=8, quantity=2, client_price=65998, status="CREATED"),
            Order(user_id=9, product_id=7, quantity=1, client_price=4999, status="CONFIRMED"),
            Order(user_id=10, product_id=1, quantity=1, client_price=159999, status="CREATED"),
        ]
        db.session.add_all(demo_orders)
        db.session.commit()

    # ensure logs table exists
    db.session.commit()


def current_user_id():
    """JWT identity is stored as string -> parse safely."""
    ident = get_jwt_identity()
    try:
        return int(ident)
    except Exception:
        return None


# ------------------------------------------------------------
# Logging helper
# ------------------------------------------------------------
def log_exploit(event_type, endpoint, payload=None, note=None):
    try:
        uid = None
        try:
            uid = current_user_id()
        except Exception:
            uid = None
        ip = request.remote_addr if request else None
        entry = ExploitLog(user_id=uid, event_type=event_type, endpoint=endpoint, payload=json.dumps(payload) if payload else None, ip=ip, note=note)
        db.session.add(entry)
        db.session.commit()
    except Exception:
        # Logging should not interrupt primary flow
        db.session.rollback()


# ============================================================
# Health & Setup
# ============================================================

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "VulnShop API", "time": int(time.time())})


# ============================================================
# Dashboard & Static Files
# ============================================================

@app.get("/")
def dashboard():
    """Serve the interactive dashboard."""
    try:
        with open("Dashboard_Interactive.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return html_content, 200, {"Content-Type": "text/html"}
    except FileNotFoundError:
        return jsonify({"error": "Dashboard not found"}), 404


@app.post("/api/setup/reset")
def reset_db():
    """INTENTIONALLY UNSAFE: no auth. Useful for classroom resets."""
    db.drop_all()
    db.create_all()
    seed_data()
    return jsonify({"ok": True, "message": "Database reset & seeded."})


# ============================================================
# AUTH (API2: Broken Authentication)
# - plaintext passwords
# - no rate limiting
# - weak JWT secret default
# ============================================================

@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()
    if not user or user.password != password:
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    # JWT identity stores user_id only (role not enforced anywhere properly)
    token = create_access_token(identity=str(user.id))
    return jsonify({"ok": True, "access_token": token, "user": user.to_dict()})


# ============================================================
# USERS (API1 BOLA + API3 Property issues)
# ============================================================

@app.get("/api/users")
def list_users():
    """List all users (info endpoint for dashboard)"""
    users = User.query.all()
    return jsonify({"ok": True, "users": [u.to_dict() for u in users]})


@app.get("/api/users/<int:user_id>")
@jwt_required()
def get_user(user_id):
    # API1: BOLA - no ownership check; any authenticated user can access any user
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    # Log potential BOLA access
    log_exploit(event_type="BOLA_READ_USER", endpoint=f"/api/users/{user_id}", payload={"target_user": user_id}, note="User profile read via BOLA demo")
    return jsonify({"ok": True, "user": user.to_dict()})


@app.patch("/api/users/<int:user_id>")
@jwt_required()
def patch_user(user_id):
    # API3: Broken Object Property Level Auth (Mass assignment)
    # Allows changing role/is_admin/balance/password etc.
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    payload = request.get_json(force=True, silent=True) or {}
    for k, v in payload.items():
        if hasattr(user, k):
            setattr(user, k, v)  # BAD: mass assignment + no authorization checks
    db.session.commit()
    # Log mass-assignment exploit attempt
    log_exploit(event_type="MASS_ASSIGNMENT", endpoint=f"/api/users/{user_id}", payload=payload, note="Mass assignment demo - privileged fields updated")
    return jsonify({"ok": True, "user": user.to_dict(), "note": "Mass assignment vulnerability demo."})


# ============================================================
# PRODUCTS (API4 Resource Consumption + API5 Function auth issues)
# ============================================================

@app.get("/api/products")
def list_products():
    # API4: Unrestricted Resource Consumption - no auth required; no cap for limit
    limit = request.args.get("limit", default="10")
    offset = request.args.get("offset", default="0")

    try:
        limit_i = int(limit)
        offset_i = int(offset)
    except ValueError:
        return jsonify({"ok": False, "error": "limit/offset must be integers"}), 400

    items = Product.query.offset(offset_i).limit(limit_i).all()
    # Log high-limit requests for resource exhaustion awareness
    try:
        if limit_i and limit_i > 10000:
            log_exploit(event_type="RESOURCE_EXHAUSTION_ATTEMPT", endpoint="/api/products", payload={"limit": limit_i}, note="Large limit requested - potential DoS")
    except Exception:
        pass
    return jsonify({"ok": True, "count": len(items), "products": [p.to_dict() for p in items]})


@app.delete("/api/products/<int:product_id>")
@jwt_required()
def delete_product(product_id):
    # API5: Broken Function Level Authorization - no role check; any user can delete products
    p = Product.query.get(product_id)
    if not p:
        return jsonify({"ok": False, "error": "Product not found"}), 404
    db.session.delete(p)
    db.session.commit()
    log_exploit(event_type="DELETE_PRODUCT", endpoint=f"/api/products/{product_id}", payload={"deleted_product_id": product_id}, note="Product deleted without role check")
    return jsonify({"ok": True, "deleted_product_id": product_id, "note": "No role check demo."})


# ============================================================
# ORDERS (API1 BOLA + API6 Business flow + API3 price trust)
# ============================================================

@app.get("/api/orders")
def list_orders():
    """List all orders (info endpoint for dashboard)"""
    orders = Order.query.all()
    return jsonify({"ok": True, "orders": [o.to_dict() for o in orders]})


@app.post("/api/orders")
@jwt_required()
def create_order():
    # Creates an order and TRUSTS client_price (BAD) for teaching API3/API6
    uid = current_user_id()
    if uid is None:
        return jsonify({"ok": False, "error": "Bad token identity"}), 401

    data = request.get_json(force=True, silent=True) or {}
    product_id = int(data.get("product_id", 0))
    quantity = int(data.get("quantity", 1))
    client_price = int(data.get("price", 0))  # BAD: client controlled

    p = Product.query.get(product_id)
    if not p:
        return jsonify({"ok": False, "error": "Product not found"}), 404

    # BAD: doesn't validate stock properly, doesn't compute price server-side
    o = Order(user_id=uid, product_id=product_id, quantity=quantity, client_price=client_price, status="CREATED")
    db.session.add(o)
    db.session.commit()
    log_exploit(event_type="CREATE_ORDER", endpoint="/api/orders", payload={"order_id": o.id, "client_price": client_price}, note="Order created (client price trusted)")
    return jsonify({"ok": True, "order": o.to_dict(), "note": "Client controls price demo."})


@app.get("/api/orders/<int:order_id>")
@jwt_required()
def get_order(order_id):
    # API1: BOLA - no ownership check; any authenticated user can read any order
    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404
    # Log BOLA order read
    log_exploit(event_type="BOLA_READ_ORDER", endpoint=f"/api/orders/{order_id}", payload={"order_id": order_id}, note="Order accessed without ownership check")
    return jsonify({"ok": True, "order": o.to_dict()})


@app.post("/api/orders/<int:order_id>/pay")
@jwt_required()
def pay_order(order_id):
    # Very weak payment flow (intentionally)
    uid = current_user_id()
    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    # BAD: doesn't verify ownership; doesn't verify amount; doesn't verify payment provider
    o.status = "PAID"
    db.session.commit()
    log_exploit(event_type="PAY_ORDER", endpoint=f"/api/orders/{order_id}/pay", payload={"order_id": order_id}, note="Order payment flow (weak) invoked")
    return jsonify({"ok": True, "order": o.to_dict(), "note": "Payment flow is intentionally weak."})


@app.post("/api/orders/<int:order_id>/confirm")
@jwt_required()
def confirm_order(order_id):
    # API6: Unrestricted Access to Sensitive Business Flows
    # BAD: allows confirming even if not PAID
    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    o.status = "CONFIRMED"  # BAD: no check for PAID
    db.session.commit()
    log_exploit(event_type="CONFIRM_ORDER", endpoint=f"/api/orders/{order_id}/confirm", payload={"order_id": order_id}, note="Order confirmed without enforcing payment")
    return jsonify({"ok": True, "order": o.to_dict(), "note": "Confirm works without enforcing payment."})


# ============================================================
# SSRF (API7)
# ============================================================

@app.post("/api/utils/fetch-url")
@jwt_required()
def fetch_url():
    """
    API7: SSRF - Fetches a remote resource without validating the URI.
    Accepts JSON: {"url": "http://example.com"}
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")

    if not url:
        return jsonify({"ok": False, "error": "url required"}), 400

    # BAD: no validation of scheme/host/IP ranges
    try:
        r = requests.get(url, timeout=3)
        log_exploit(event_type="SSRF", endpoint="/api/utils/fetch-url", payload={"url": url}, note="SSRF demo - fetched external/internal URL")
        return jsonify({
            "ok": True,
            "fetched_url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body_preview": r.text[:500],
            "note": "SSRF demo. No URL validation.",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ============================================================
# ADMIN (API5 function-level auth failure)
# ============================================================

@app.get("/api/admin/users")
@jwt_required()
def admin_list_users():
    # API5: Broken Function Level Authorization - should be admin only, but isn't
    users = User.query.all()
    log_exploit(event_type="ADMIN_ENDPOINT_ACCESS", endpoint="/api/admin/users", payload={}, note="Admin endpoint accessed without proper role check")
    return jsonify({"ok": True, "users": [u.to_dict() for u in users], "note": "Admin endpoint without role check."})


# ============================================================
# Inventory / old version (API9)
# ============================================================

@app.get("/api/v1/debug/users")
def v1_debug_users():
    # API9: Improper inventory management - old debug endpoint still exposed, no auth
    users = User.query.all()
    log_exploit(event_type="DEBUG_ENDPOINT_ACCESS", endpoint="/api/v1/debug/users", payload={}, note="Legacy debug endpoint accessed (no auth)")
    return jsonify({"ok": True, "users": [u.to_dict() for u in users], "note": "Legacy v1 debug endpoint exposed."})


@app.get("/api/logs")
@jwt_required()
def get_logs():
    """Admin-only endpoint to fetch exploit logs (audit trail)."""
    uid = current_user_id()
    user = User.query.get(uid) if uid else None
    if not user or not user.is_admin:
        # record unauthorized attempt
        log_exploit(event_type="UNAUTHORIZED_LOG_ACCESS", endpoint="/api/logs", payload={}, note="Non-admin attempted to access logs")
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    logs = ExploitLog.query.order_by(ExploitLog.timestamp.desc()).limit(1000).all()
    return jsonify({"ok": True, "logs": [l.to_dict() for l in logs]})


# ============================================================
# Unsafe consumption (API10)
# ============================================================

@app.post("/api/shipping/quote")
@jwt_required()
def shipping_quote():
    """
    API10: Unsafe Consumption of APIs
    Takes a user-provided third-party URL and trusts its response.
    Body: {"provider_url":"http://...","order_id":1}
    Expects provider returns JSON: {"quote": 123}
    """
    data = request.get_json(force=True, silent=True) or {}
    provider_url = data.get("provider_url", "")
    order_id = int(data.get("order_id", 0))

    if not provider_url or not order_id:
        return jsonify({"ok": False, "error": "provider_url and order_id required"}), 400

    o = Order.query.get(order_id)
    if not o:
        return jsonify({"ok": False, "error": "Order not found"}), 404

    # BAD: doesn't validate provider domain, doesn't validate signature, trusts quote
    try:
        resp = requests.get(provider_url, timeout=3)
        payload = resp.json()  # BAD: trust blindly
        quote = payload.get("quote", 0)
        return jsonify({
            "ok": True,
            "order_id": order_id,
            "provider_url": provider_url,
            "trusted_quote": quote,
            "note": "Unsafe third-party consumption demo (no allowlist/signature).",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ============================================================
# Start
# ============================================================

if __name__ == "__main__":
    with app.app_context():
        seed_data()

    # Bind to all interfaces so student machines can hit it on LAN
    # Instructor machine IP: http://<your-ip>:5000
    app.run(host="0.0.0.0", port=5000, debug=True)
