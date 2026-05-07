import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from secrets import token_urlsafe

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(__file__)
DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "xmarkt.db"))
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(BASE_DIR, "static", "uploads"))
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}

app = Flask("X-Markt")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Bitte melde dich an."

CATEGORIES = [
    {"slug": "auto-rad-boot", "name": "Auto, Rad & Boot"},
    {"slug": "immobilien", "name": "Immobilien"},
    {"slug": "jobs", "name": "Jobs"},
    {"slug": "haus-garten", "name": "Haus & Garten"},
    {"slug": "elektronik", "name": "Elektronik"},
    {"slug": "familie-kind-baby", "name": "Familie, Kind & Baby"},
    {"slug": "freizeit-hobby-nachbarschaft", "name": "Freizeit, Hobby & Nachbarschaft"},
    {"slug": "haustiere", "name": "Haustiere"},
    {"slug": "mode-beauty", "name": "Mode & Beauty"},
    {"slug": "eintrittskarten-tickets", "name": "Eintrittskarten & Tickets"},
    {"slug": "dienstleistungen", "name": "Dienstleistungen"},
    {"slug": "unterricht-kurse", "name": "Unterricht & Kurse"},
    {"slug": "verschenken-tauschen", "name": "Verschenken & Tauschen"},
]


class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.email = row["email"]
        self.display_name = row["display_name"]
        self.is_admin = bool(row["is_admin"])


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def execute(sql, params=()):
    connection = db()
    cursor = connection.execute(sql, params)
    connection.commit()
    return cursor


def query_all(sql, params=()):
    return db().execute(sql, params).fetchall()


def query_one(sql, params=()):
    return db().execute(sql, params).fetchone()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def category_name(slug):
    return next((category["name"] for category in CATEGORIES if category["slug"] == slug), slug)


def category_slug(name):
    normalized = name.lower().replace("&", "").replace(",", "").replace(" ", "-")
    return next((category["slug"] for category in CATEGORIES if category["name"] == name), normalized)


def euro_to_cents(value):
    try:
        return max(0, int(round(float((value or "0").replace(",", ".")) * 100)))
    except ValueError:
        return 0


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True) if os.path.dirname(DATABASE_PATH) else None
    connection = sqlite3.connect(DATABASE_PATH)
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price_cents INTEGER NOT NULL DEFAULT 0,
            category_slug TEXT NOT NULL,
            category_name TEXT NOT NULL,
            plz TEXT NOT NULL,
            city TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS ad_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            image_url TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (ad_id) REFERENCES ads(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            user_id INTEGER,
            reason TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(ad_id, buyer_id, seller_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
        );
        """
    )
    connection.commit()
    connection.close()


@login_manager.user_loader
def load_user(user_id):
    row = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    return User(row) if row else None


@app.context_processor
def inject_globals():
    return {"categories": CATEGORIES, "category_name": category_name, "csrf_token": csrf_token}


@app.before_request
def protect_csrf():
    if request.method == "POST":
        sent_token = request.form.get("_csrf_token")
        if not sent_token or sent_token != session.get("_csrf_token"):
            abort(400)


@app.before_request
def ensure_database():
    init_db()


def ad_listing_query(where="", params=()):
    return query_all(
        f"""
        SELECT ads.*, users.display_name AS seller_name,
               COALESCE((SELECT image_url FROM ad_images WHERE ad_id = ads.id ORDER BY sort_order LIMIT 1), '/static/placeholder.jpg') AS image_url
        FROM ads
        JOIN users ON users.id = ads.user_id
        WHERE ads.status = 'active' {where}
        ORDER BY ads.created_at DESC
        """,
        params,
    )


@app.route("/")
def index():
    filters = []
    params = []
    q = request.args.get("q", "").strip()
    plz = request.args.get("plz", "").strip()
    if q:
        filters.append("AND (ads.title LIKE ? OR ads.description LIKE ? OR ads.city LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if plz:
        filters.append("AND ads.plz LIKE ?")
        params.append(f"{plz}%")
    return render_template(
        "index.html",
        title="X-Markt.de - Kleinanzeigen",
        ads=ad_listing_query(" ".join(filters), params),
    )


@app.route("/search")
def search():
    return redirect(url_for("index", **request.args.to_dict()))


@app.route("/k/<slug>")
def category(slug):
    return render_template(
        "index.html",
        title=f"{category_name(slug)} - X-Markt.de",
        ads=ad_listing_query("AND ads.category_slug = ?", (slug,)),
    )


@app.route("/ad/<int:ad_id>")
def detail(ad_id):
    ad = query_one(
        """
        SELECT ads.*, users.display_name AS seller_name
        FROM ads
        JOIN users ON users.id = ads.user_id
        WHERE ads.id = ? AND ads.status = 'active'
        """,
        (ad_id,),
    )
    if not ad:
        flash("Anzeige nicht gefunden.")
        return redirect(url_for("index"))
    images = query_all("SELECT image_url FROM ad_images WHERE ad_id = ? ORDER BY sort_order", (ad_id,))
    return render_template("detail.html", ad=ad, images=images)


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_ad():
    if request.method == "GET":
        return render_template("new.html")

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    selected_category = request.form.get("category", "").strip()
    plz = request.form.get("plz", "").strip()
    city = request.form.get("city", "").strip()
    price_cents = euro_to_cents(request.form.get("price"))

    if len(title) < 3 or len(description) < 10 or not plz or not city or selected_category not in [c["name"] for c in CATEGORIES]:
        flash("Bitte pruefe Titel, Beschreibung, Kategorie, PLZ und Ort.")
        return render_template("new.html"), 400

    now = datetime.utcnow().isoformat(timespec="seconds")
    cursor = execute(
        """
        INSERT INTO ads (user_id, title, description, price_cents, category_slug, category_name, plz, city, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (int(current_user.id), title, description, price_cents, category_slug(selected_category), selected_category, plz, city, now, now),
    )
    ad_id = cursor.lastrowid

    for index, file in enumerate(request.files.getlist("images")[:5]):
        if file and file.filename and allowed_file(file.filename):
            extension = file.filename.rsplit(".", 1)[1].lower()
            filename = secure_filename(f"{uuid.uuid4().hex}.{extension}")
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            execute(
                "INSERT INTO ad_images (ad_id, image_url, sort_order) VALUES (?, ?, ?)",
                (ad_id, f"/static/uploads/{filename}", index),
            )

    flash("Anzeige wurde veroeffentlicht.")
    return redirect(url_for("detail", ad_id=ad_id))


@app.route("/report/<int:ad_id>", methods=["POST", "GET"])
def report_ad(ad_id):
    reason = request.form.get("reason", "").strip() if request.method == "POST" else ""
    execute(
        "INSERT INTO reports (ad_id, user_id, reason, created_at) VALUES (?, ?, ?, ?)",
        (ad_id, int(current_user.id) if current_user.is_authenticated else None, reason, datetime.utcnow().isoformat(timespec="seconds")),
    )
    flash("Danke, wir pruefen diese Anzeige.")
    return redirect(url_for("detail", ad_id=ad_id))


@app.route("/inbox")
@login_required
def inbox():
    threads = query_all(
        """
        SELECT threads.*, ads.title AS ad_title,
               CASE WHEN threads.buyer_id = ? THEN seller.display_name ELSE buyer.display_name END AS other_name,
               (SELECT body FROM messages WHERE thread_id = threads.id ORDER BY id DESC LIMIT 1) AS last_text
        FROM threads
        JOIN ads ON ads.id = threads.ad_id
        JOIN users buyer ON buyer.id = threads.buyer_id
        JOIN users seller ON seller.id = threads.seller_id
        WHERE threads.buyer_id = ? OR threads.seller_id = ?
        ORDER BY threads.updated_at DESC
        """,
        (int(current_user.id), int(current_user.id), int(current_user.id)),
    )
    return render_template("inbox.html", threads=threads, active_thread=None, messages=[])


@app.route("/thread/<int:thread_id>")
@login_required
def thread(thread_id):
    thread_row = query_one("SELECT * FROM threads WHERE id = ? AND (buyer_id = ? OR seller_id = ?)", (thread_id, int(current_user.id), int(current_user.id)))
    if not thread_row:
        flash("Thread nicht gefunden.")
        return redirect(url_for("inbox"))
    messages = query_all(
        """
        SELECT messages.*, users.display_name AS sender_name
        FROM messages
        JOIN users ON users.id = messages.sender_id
        WHERE thread_id = ?
        ORDER BY messages.id
        """,
        (thread_id,),
    )
    other_id = thread_row["seller_id"] if thread_row["buyer_id"] == int(current_user.id) else thread_row["buyer_id"]
    other_user = query_one("SELECT display_name AS name FROM users WHERE id = ?", (other_id,))
    return render_template("thread.html", thread=thread_row, other_user=other_user, messages=messages)


@app.route("/thread/<int:thread_id>/send", methods=["POST"])
@login_required
def send_message(thread_id):
    thread_row = query_one("SELECT * FROM threads WHERE id = ? AND (buyer_id = ? OR seller_id = ?)", (thread_id, int(current_user.id), int(current_user.id)))
    if not thread_row:
        abort(404)
    text = request.form.get("text", "").strip()
    if text:
        now = datetime.utcnow().isoformat(timespec="seconds")
        execute("INSERT INTO messages (thread_id, sender_id, body, created_at) VALUES (?, ?, ?, ?)", (thread_id, int(current_user.id), text, now))
        execute("UPDATE threads SET updated_at = ? WHERE id = ?", (now, thread_id))
    return redirect(url_for("thread", thread_id=thread_id))


@app.route("/thread/with/<int:user_id>")
@login_required
def thread_with(user_id):
    ad_id = int(request.args.get("ad_id", 0))
    ad = query_one("SELECT * FROM ads WHERE id = ? AND user_id = ?", (ad_id, user_id))
    if not ad or user_id == int(current_user.id):
        flash("Kontakt ist fuer diese Anzeige nicht moeglich.")
        return redirect(url_for("detail", ad_id=ad_id) if ad_id else url_for("index"))
    now = datetime.utcnow().isoformat(timespec="seconds")
    execute(
        "INSERT OR IGNORE INTO threads (ad_id, buyer_id, seller_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (ad_id, int(current_user.id), user_id, now, now),
    )
    thread_row = query_one("SELECT id FROM threads WHERE ad_id = ? AND buyer_id = ? AND seller_id = ?", (ad_id, int(current_user.id), user_id))
    return redirect(url_for("thread", thread_id=thread_row["id"]))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        row = query_one("SELECT * FROM users WHERE email = ?", (email,))
        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row))
            flash("Du bist eingeloggt.")
            return redirect(request.args.get("next") or url_for("index"))
        flash("E-Mail oder Passwort stimmt nicht.")
    return render_template("login.html", title="Login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        if not email or len(display_name) < 2 or len(password) < 10:
            flash("Bitte gib E-Mail, Anzeigenname und ein Passwort mit mindestens 10 Zeichen ein.")
            return render_template("register.html", title="Registrieren"), 400
        try:
            execute(
                "INSERT INTO users (email, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, display_name, generate_password_hash(password), datetime.utcnow().isoformat(timespec="seconds")),
            )
        except sqlite3.IntegrityError:
            flash("Diese E-Mail ist bereits registriert.")
            return render_template("register.html", title="Registrieren"), 400
        row = query_one("SELECT * FROM users WHERE email = ?", (email,))
        login_user(User(row))
        flash("Konto erstellt. Willkommen bei X-Markt.de.")
        return redirect(url_for("index"))
    return render_template("register.html", title="Registrieren")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Du bist ausgeloggt.")
    return redirect(url_for("index"))


@app.route("/admin")
@admin_required
def admin():
    stats = {
        "users": query_one("SELECT COUNT(*) AS count FROM users")["count"],
        "ads": query_one("SELECT COUNT(*) AS count FROM ads")["count"],
        "reports": query_one("SELECT COUNT(*) AS count FROM reports")["count"],
    }
    return render_template("admin.html", title="Admin", stats=stats)


@app.route("/impressum")
def impressum():
    return render_template("impressum.html", title="Impressum")


@app.route("/datenschutz")
def datenschutz():
    return render_template("datenschutz.html", title="Datenschutz")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG") == "1")
