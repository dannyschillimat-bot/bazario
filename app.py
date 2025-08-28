import os
import math
import sqlite3
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, request, redirect, url_for, render_template, send_from_directory,
    flash, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)

APP_NAME = "Bazario"
DB_PATH = "bazario.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}

CATEGORIES = [
    "Elektronik", "Möbel", "Kleidung", "Fahrzeuge",
    "Haushalt", "Freizeit", "Bücher", "Tickets", "Sonstiges"
]

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = "dev-secret-change-me"  # in PROD per ENV setzen
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# ---------------- DB Helpers ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as db:
        # Users
        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            pw_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """)
        # PLZ (per import_plz.py befüllt)
        db.execute("""
        CREATE TABLE IF NOT EXISTS plz (
            plz TEXT PRIMARY KEY,
            ort TEXT NOT NULL,
            lat REAL NOT NULL,
            lon REAL NOT NULL
        )
        """)
        # Ads
        db.execute("""
        CREATE TABLE IF NOT EXISTS ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            price_cents INTEGER NOT NULL DEFAULT 0,
            image_filename TEXT,
            plz TEXT NOT NULL,
            ort TEXT NOT NULL,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(plz) REFERENCES plz(plz)
        )
        """)
        # Threads (Konversationen pro Anzeige & Käufer)
        db.execute("""
        CREATE TABLE IF NOT EXISTS threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(ad_id, buyer_id),
            FOREIGN KEY(ad_id) REFERENCES ads(id) ON DELETE CASCADE,
            FOREIGN KEY(buyer_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        # Messages (Nachrichten in Threads)
        db.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY(thread_id) REFERENCES threads(id) ON DELETE CASCADE,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        # Reports (Melden-Funktion)
        db.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            target_type TEXT NOT NULL CHECK(target_type IN ('ad','message','thread')),
            target_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','ignored','removed')),
            created_at TEXT NOT NULL,
            handled_by INTEGER,
            handled_at TEXT,
            FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(handled_by) REFERENCES users(id) ON DELETE SET NULL
        )
        """)

init_db()

import os as _os, sqlite3 as _sqlite3

def _auto_import_plz():
    try:
        db = _sqlite3.connect(DB_PATH)
        c = db.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='plz'")
        if not c.fetchone():
            db.close()
            return
        c.execute("SELECT COUNT(*) FROM plz")
        n = c.fetchone()[0]
        db.close()
        # Nur wenn leer und CSV vorhanden:
        if n == 0 and _os.path.exists("de_plz.csv"):
            import import_plz  # führt den Import aus
            print("PLZ-Autoimport ausgeführt.")
    except Exception as e:
        print("PLZ-Autoimport fehlgeschlagen:", e)

_auto_import_plz()

def ensure_admin_from_env():
    email = os.environ.get("BAZARIO_ADMIN_EMAIL")
    if not email:
        return
    with get_db() as db:
        row = db.execute("SELECT id FROM users WHERE email = ?", (email.lower(),)).fetchone()
        if row:
            db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (row["id"],))
ensure_admin_from_env()

# ---------------- Auth Model ----------------
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.is_admin = bool(row["is_admin"])

@login_manager.user_loader
def load_user(user_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return User(row) if row else None

# ---------------- Utils ----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def km_distance(lat1, lon1, lat2, lon2):
    R = 6371.0
    import math
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return 2 * R * math.asin(math.sqrt(a))

def plz_to_coords(db, plz):
    return db.execute("SELECT * FROM plz WHERE plz = ?", (plz,)).fetchone()

def require_thread_participant(thread_row):
    if not current_user.is_authenticated:
        abort(403)
    if current_user.id not in (thread_row["buyer_id"], thread_row["seller_id"]):
        abort(403)

# ---------------- Routes: Auth ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("E-Mail und Passwort sind Pflicht.")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)
        try:
            with get_db() as db:
                cur = db.execute("""
                    INSERT INTO users (email, pw_hash, created_at) VALUES (?, ?, ?)
                """, (email, pw_hash, datetime.utcnow().isoformat()))
                user_id = cur.lastrowid
                row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                login_user(User(row))
        except sqlite3.IntegrityError:
            flash("E-Mail ist bereits registriert.")
            return redirect(url_for("register"))
        return redirect(url_for("index"))

    return render_template("register.html", title=f"{APP_NAME} – Registrieren")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not row or not check_password_hash(row["pw_hash"], password):
                flash("Login fehlgeschlagen.")
                return redirect(url_for("login"))
            login_user(User(row))
        return redirect(url_for("index"))
    return render_template("login.html", title=f"{APP_NAME} – Login")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# ---------------- Routes: Ads & Suche ----------------
@app.route("/")
def index():
    q = (request.args.get("q") or "").strip()
    cat = (request.args.get("cat") or "").strip()
    base_plz = (request.args.get("plz") or "").strip()
    try:
        radius_km = int(request.args.get("radius") or "0")
    except ValueError:
        radius_km = 0

    with get_db() as db:
        ads = db.execute("""
            SELECT * FROM ads
            ORDER BY datetime(created_at) DESC
        """).fetchall()

        if q:
            qq = q.lower()
            ads = [r for r in ads if (qq in r["title"].lower() or qq in r["description"].lower())]
        if cat:
            ads = [r for r in ads if r["category"] == cat]
        if base_plz and radius_km > 0:
            base = plz_to_coords(db, base_plz)
            if base:
                clat, clon = base["lat"], base["lon"]
                ads = [r for r in ads if km_distance(clat, clon, r["lat"], r["lon"]) <= radius_km]
            else:
                flash("PLZ nicht gefunden. Filter ignoriert.")

    return render_template(
        "index.html",
        title=APP_NAME,
        ads=ads, q=q, cat=cat, categories=CATEGORIES,
        plz=base_plz, radius=radius_km
    )

@app.route("/ad/new", methods=["GET", "POST"])
@login_required
def new_ad():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        category = (request.form.get("category") or "").strip() or "Sonstiges"
        price_eur = (request.form.get("price") or "0").strip().replace(",", ".")
        plz = (request.form.get("plz") or "").strip()
        image = request.files.get("image")

        if not title or not description or not plz:
            flash("Titel, Beschreibung und PLZ sind Pflicht.")
            return redirect(url_for("new_ad"))
        if category not in CATEGORIES:
            category = "Sonstiges"

        try:
            price_cents = int(round(float(price_eur) * 100))
            price_cents = max(price_cents, 0)
        except ValueError:
            price_cents = 0

        with get_db() as db:
            place = plz_to_coords(db, plz)
            if not place:
                flash("PLZ existiert nicht.")
                return redirect(url_for("new_ad"))

            filename = None
            if image and image.filename:
                if not allowed_file(image.filename):
                    flash("Ungültiges Bildformat. Erlaubt: png, jpg, jpeg, gif.")
                    return redirect(url_for("new_ad"))
                filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(image.filename)
                image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            db.execute("""
                INSERT INTO ads (user_id, title, description, category, price_cents, image_filename,
                                 plz, ort, lat, lon, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                current_user.id, title, description, category, price_cents, filename,
                place["plz"], place["ort"], place["lat"], place["lon"],
                datetime.utcnow().isoformat()
            ))
        return redirect(url_for("index"))

    return render_template("new.html", title=f"{APP_NAME} – Neue Anzeige", categories=CATEGORIES)

@app.route("/ad/<int:ad_id>")
def detail(ad_id):
    with get_db() as db:
        ad = db.execute("SELECT * FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return ("Anzeige nicht gefunden", 404)
    # Button: Kontakt aufnehmen, wenn eingeloggt und nicht eigener Artikel
    can_contact = current_user.is_authenticated and (not current_user.is_anonymous) and current_user.id != ad["user_id"]
    return render_template("detail.html", title=f"{APP_NAME} – Anzeige", ad=ad, can_contact=can_contact)

# ---------------- Chat / Threads ----------------
@app.route("/ad/<int:ad_id>/contact", methods=["POST"])
@login_required
def contact_seller(ad_id):
    with get_db() as db:
        ad = db.execute("SELECT * FROM ads WHERE id = ?", (ad_id,)).fetchone()
        if not ad:
            abort(404)
        if ad["user_id"] == current_user.id:
            flash("Du kannst deine eigene Anzeige nicht kontaktieren.")
            return redirect(url_for("detail", ad_id=ad_id))

        # Thread holen/erstellen
        row = db.execute("""
            SELECT * FROM threads WHERE ad_id = ? AND buyer_id = ?
        """, (ad_id, current_user.id)).fetchone()
        if not row:
            cur = db.execute("""
                INSERT INTO threads (ad_id, buyer_id, seller_id, created_at)
                VALUES (?, ?, ?, ?)
            """, (ad_id, current_user.id, ad["user_id"], datetime.utcnow().isoformat()))
            thread_id = cur.lastrowid
        else:
            thread_id = row["id"]
    return redirect(url_for("thread_view", thread_id=thread_id))

@app.route("/inbox")
@login_required
def inbox():
    with get_db() as db:
        threads = db.execute("""
            SELECT t.*, a.title AS ad_title, a.image_filename AS ad_image, a.price_cents,
                   a.ort, a.plz,
                   u1.email AS buyer_email, u2.email AS seller_email,
                   (
                     SELECT body FROM messages m2
                     WHERE m2.thread_id = t.id
                     ORDER BY datetime(m2.created_at) DESC
                     LIMIT 1
                   ) AS last_body,
                   (
                     SELECT COUNT(*) FROM messages m3
                     WHERE m3.thread_id = t.id
                       AND m3.sender_id != ?
                       AND m3.read_at IS NULL
                   ) AS unread_count
            FROM threads t
            JOIN ads a ON a.id = t.ad_id
            JOIN users u1 ON u1.id = t.buyer_id
            JOIN users u2 ON u2.id = t.seller_id
            WHERE t.buyer_id = ? OR t.seller_id = ?
            ORDER BY datetime(t.created_at) DESC
        """, (current_user.id, current_user.id, current_user.id)).fetchall()
    return render_template("inbox.html", title=f"{APP_NAME} – Nachrichten", threads=threads)

@app.route("/thread/<int:thread_id>", methods=["GET", "POST"])
@login_required
def thread_view(thread_id):
    with get_db() as db:
        t = db.execute("""
            SELECT t.*, a.title AS ad_title, a.id AS ad_id,
                   u1.email AS buyer_email, u2.email AS seller_email
            FROM threads t
            JOIN ads a ON a.id = t.ad_id
            JOIN users u1 ON u1.id = t.buyer_id
            JOIN users u2 ON u2.id = t.seller_id
            WHERE t.id = ?
        """, (thread_id,)).fetchone()
        if not t:
            abort(404)
        require_thread_participant(t)

        # POST = neue Nachricht
        if request.method == "POST":
            body = (request.form.get("body") or "").strip()
            if not body:
                flash("Nachricht ist leer.")
                return redirect(url_for("thread_view", thread_id=thread_id))
            if len(body) > 2000:
                body = body[:2000]
            db.execute("""
                INSERT INTO messages (thread_id, sender_id, body, created_at)
                VALUES (?, ?, ?, ?)
            """, (thread_id, current_user.id, body, datetime.utcnow().isoformat()))
            return redirect(url_for("thread_view", thread_id=thread_id))

        # als gelesen markieren (alles, was vom Gegenüber ist)
        db.execute("""
            UPDATE messages
            SET read_at = ?
            WHERE thread_id = ? AND sender_id != ? AND read_at IS NULL
        """, (datetime.utcnow().isoformat(), thread_id, current_user.id))
        msgs = db.execute("""
            SELECT m.*, u.email AS sender_email
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.thread_id = ?
            ORDER BY datetime(m.created_at) ASC
        """, (thread_id,)).fetchall()

    return render_template("thread.html", title=f"{APP_NAME} – Chat", t=t, msgs=msgs)

# ---------------- Reporting ----------------
@app.route("/report/ad/<int:ad_id>", methods=["POST"])
@login_required
def report_ad(ad_id):
    reason = (request.form.get("reason") or "").strip()
    if not reason:
        flash("Bitte einen Grund angeben.")
        return redirect(url_for("detail", ad_id=ad_id))
    with get_db() as db:
        exists = db.execute("SELECT id FROM ads WHERE id = ?", (ad_id,)).fetchone()
        if not exists:
            abort(404)
        db.execute("""
            INSERT INTO reports (reporter_id, target_type, target_id, reason, created_at)
            VALUES (?, 'ad', ?, ?, ?)
        """, (current_user.id, ad_id, reason, datetime.utcnow().isoformat()))
    flash("Danke für die Meldung. Wir prüfen das.")
    return redirect(url_for("detail", ad_id=ad_id))

@app.route("/report/message/<int:msg_id>", methods=["POST"])
@login_required
def report_message(msg_id):
    reason = (request.form.get("reason") or "").strip()
    if not reason:
        flash("Bitte einen Grund angeben.")
        with get_db() as db:
            m = db.execute("SELECT thread_id FROM messages WHERE id = ?", (msg_id,)).fetchone()
        return redirect(url_for("thread_view", thread_id=m["thread_id"] if m else 0))
    with get_db() as db:
        m = db.execute("""
            SELECT m.*, t.buyer_id, t.seller_id FROM messages m
            JOIN threads t ON t.id = m.thread_id
            WHERE m.id = ?
        """, (msg_id,)).fetchone()
        if not m:
            abort(404)
        if current_user.id not in (m["buyer_id"], m["seller_id"]):
            abort(403)
        db.execute("""
            INSERT INTO reports (reporter_id, target_type, target_id, reason, created_at)
            VALUES (?, 'message', ?, ?, ?)
        """, (current_user.id, msg_id, reason, datetime.utcnow().isoformat()))
    flash("Nachricht gemeldet.")
    return redirect(url_for("thread_view", thread_id=m["thread_id"]))

# ---------------- Admin: Reports ----------------
def admin_required():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

@app.route("/admin/reports")
@login_required
def admin_reports():
    admin_required()
    status = (request.args.get("status") or "open").strip()
    with get_db() as db:
        rows = db.execute(f"""
            SELECT r.*, u.email AS reporter_email
            FROM reports r
            JOIN users u ON u.id = r.reporter_id
            WHERE r.status = ?
            ORDER BY datetime(r.created_at) DESC
        """, (status,)).fetchall()
    return render_template("admin_reports.html", title=f"{APP_NAME} – Reports", rows=rows, status=status)

@app.route("/admin/reports/<int:rid>/ignore", methods=["POST"])
@login_required
def admin_report_ignore(rid):
    admin_required()
    with get_db() as db:
        db.execute("""
            UPDATE reports
            SET status='ignored', handled_by=?, handled_at=?
            WHERE id=?
        """, (current_user.id, datetime.utcnow().isoformat(), rid))
    return redirect(url_for("admin_reports"))

@app.route("/admin/reports/<int:rid>/remove", methods=["POST"])
@login_required
def admin_report_remove(rid):
    admin_required()
    with get_db() as db:
        r = db.execute("SELECT * FROM reports WHERE id = ?", (rid,)).fetchone()
        if not r:
            abort(404)
        if r["target_type"] == "ad":
            db.execute("DELETE FROM ads WHERE id = ?", (r["target_id"],))
        elif r["target_type"] == "message":
            db.execute("DELETE FROM messages WHERE id = ?", (r["target_id"],))
        else:
            db.execute("DELETE FROM threads WHERE id = ?", (r["target_id"],))
        db.execute("""
            UPDATE reports SET status='removed', handled_by=?, handled_at=?
            WHERE id=?
        """, (current_user.id, datetime.utcnow().isoformat(), rid))
    return redirect(url_for("admin_reports"))

# ---------------- Uploads ----------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)

# ---------------- App ----------------
ensure_admin_from_env()
if __name__ == "__main__":
    app.run(debug=True)
