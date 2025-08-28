import os
import sqlite3
import datetime
import shortuuid
import requests
from PIL import Image

from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, jsonify, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# PDF utils
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

# ======================================================
# ------------- Configuration --------------------------
# ======================================================

APP_SECRET = os.environ.get("SECRET_KEY", "dev_secret_change_this")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

DB_FILE = "hits.db"
OUTDIR = "generated"
os.makedirs(OUTDIR, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = APP_SECRET

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per day", "200 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# ======================================================
# ------------- Database Helpers -----------------------
# ======================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_ref TEXT,
        user_id TEXT,
        ip TEXT,
        ua TEXT,
        ts TEXT,
        lat REAL,
        lon REAL,
        city TEXT,
        region TEXT,
        country TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')

    conn.commit()
    conn.close()

def insert_hit(doc_ref, user_id, ip, ua, lat=None, lon=None,
               city=None, region=None, country=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT INTO hits
        (doc_ref, user_id, ip, ua, ts, lat, lon, city, region, country)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (doc_ref, user_id, ip, ua,
         datetime.datetime.utcnow().isoformat()+"Z",
         lat, lon, city, region, country)
    )
    conn.commit()
    conn.close()

def fetch_hits(limit=1000):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''SELECT id, doc_ref, user_id, ip, ua, ts,
                        lat, lon, city, region, country
                 FROM hits ORDER BY id DESC LIMIT ?''', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

init_db()

# ======================================================
# ------------- Geolocation Helper ---------------------
# ======================================================

try:
    import geoip2.database
    GEO_DB = geoip2.database.Reader("GeoLite2-City.mmdb")

    def geo_ip(ip):
        try:
            r = GEO_DB.city(ip)
            return (
                r.location.latitude, r.location.longitude,
                r.city.name, r.subdivisions.most_specific.name,
                r.country.name
            )
        except Exception:
            return None, None, None, None, None
except ImportError:
    GEO_DB = None

    def geo_ip(ip):
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,lat,lon,city,regionName,country",
                timeout=4
            )
            j = r.json()
            if j.get("status") == "success":
                return j.get("lat"), j.get("lon"), j.get("city"), j.get("regionName"), j.get("country")
        except Exception:
            pass
        return None, None, None, None, None

# ======================================================
# ------------- PDF Helper -----------------------------
# ======================================================

def create_pdf_with_clickable_image(image_path: str, pdf_path: str,
                                    page_size=letter, url: str = None):
    c = canvas.Canvas(pdf_path, pagesize=page_size)
    width, height = page_size

    img = ImageReader(image_path)
    iw, ih = img.getSize()
    margin = 36
    max_w, max_h = width - 2*margin, height - 2*margin
    scale = min(max_w / iw, max_h / ih)
    draw_w, draw_h = iw * scale, ih * scale
    x = (width - draw_w) / 2
    y = (height - draw_h) / 2
    c.drawImage(img, x, y, draw_w, draw_h, preserveAspectRatio=True, mask='auto')

    if url:
        c.linkURL(url, (x, y, x + draw_w, y + draw_h), relative=0)

    c.showPage()
    c.save()

# ======================================================
# ------------- Routes ---------------------------------
# ======================================================

@app.route("/")
def index():
    return render_template("index.html", logged_in=session.get("admin", False))

# ------------------- Admin Login ----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password", "") == ADMIN_PASS:
            session["admin"] = True
            return redirect(url_for("make"))
        flash("Wrong password", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ------------------- User Auth ------------------------
@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["user_id"] = user[0]
            session["username"] = username
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for("user_login"))

    return render_template("user_login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, generate_password_hash(password)))
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("user_login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
        finally:
            conn.close()

    return render_template("register.html")

# ------------------- File Maker -----------------------
@app.route("/make", methods=["GET", "POST"])
def make():
    if not session.get("admin"):
        return redirect(url_for("login"))

    if request.method == "POST":
        mode = request.form.get("mode", "png")
        file = request.files.get("image")
        base_image = Image.open(file.stream).convert("RGBA") if file and file.filename else None

        doc_ref = shortuuid.uuid()[:8]

        if mode == "svg":
            url = url_for("clickable_redirect", doc_ref=doc_ref, _external=True)
            svg = f'''<?xml version="1.0" encoding="utf-8"?>
            <svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
              <rect width="100%" height="100%" fill="#fff"/>
              <text x="10" y="20" font-size="14">Document Ref: {doc_ref}</text>
              <image x="0" y="0" width="1" height="1" href="{url}" />
            </svg>'''
            fname = f"document_{doc_ref}.svg"
            with open(os.path.join(OUTDIR, fname), "w", encoding="utf-8") as f:
                f.write(svg)
            return render_template("made_file.html",
                                   doc_ref=doc_ref,
                                   file_url=url_for("download_generated", name=fname, _external=True),
                                   file_kind="SVG",
                                   pdf_url=None)

        # PNG Mode
        fname = f"document_{doc_ref}.png"
        fpath = os.path.join(OUTDIR, fname)

        if base_image is None:
            base_image = Image.new("RGBA", (800, 600), (255, 255, 255, 255))
        base_image.save(fpath, "PNG")

        url = url_for('clickable_redirect', doc_ref=doc_ref, _external=True)
        pdf_name = f"document_{doc_ref}.pdf"
        pdf_path = os.path.join(OUTDIR, pdf_name)
        create_pdf_with_clickable_image(fpath, pdf_path, page_size=letter, url=url)

        return render_template("made_file.html",
                               doc_ref=doc_ref,
                               file_url=url_for("download_generated", name=fname, _external=True),
                               file_kind="PNG",
                               pdf_url=url_for("download_generated", name=pdf_name, _external=True),
                               dl_pdf_url=url_for("dl_pdf", doc_ref=doc_ref, pdfname=pdf_name, _external=True))

    return render_template("make.html")

# ------------------- Clickable Redirect ----------------
@app.route("/click/<doc_ref>")
@limiter.limit("60 per minute")
def clickable_redirect(doc_ref):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")
    lat, lon, city, region, country = geo_ip(ip)
    user_id = session.get("user_id", "anonymous")

    insert_hit(doc_ref, user_id, ip, ua, lat, lon, city, region, country)

    # Redirect to a friendly landing page
    return redirect("https://your-site.com/thank-you")  # replace with your real page

# ------------------- Downloads ------------------------
@app.route("/dl_pdf/<doc_ref>/<pdfname>")
def dl_pdf(doc_ref, pdfname):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")
    lat, lon, city, region, country = geo_ip(ip)
    user_id = session.get("user_id", "anonymous")

    insert_hit(doc_ref, user_id, ip, ua, lat, lon, city, region, country)

    path = os.path.join(OUTDIR, pdfname)
    if not os.path.exists(path):
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=pdfname, mimetype="application/pdf")

@app.route("/download_generated/<name>")
def download_generated(name):
    path = os.path.join(OUTDIR, name)
    if not os.path.exists(path):
        return "Not found", 404

    ext = name.lower().split(".")[-1]
    mime_map = {
        "svg": "image/svg+xml",
        "png": "image/png",
        "html": "text/html",
        "pdf": "application/pdf"
    }
    mt = mime_map.get(ext, "application/octet-stream")

    return send_file(path, as_attachment=True, download_name=name, mimetype=mt)

# ------------------- Logs -----------------------------
@app.route("/logs")
def logs():
    if not session.get("admin"):
        return redirect(url_for("login"))

    rows = fetch_hits()
    safe_rows = [
        {
            "id": r[0], "doc_ref": r[1], "user_id": r[2],
            "ip": r[3], "ua": r[4], "ts": r[5],
            "lat": float(r[6]) if r[6] is not None else "N/A",
            "lon": float(r[7]) if r[7] is not None else "N/A",
            "city": r[8] if r[8] else "N/A",
            "region": r[9] if r[9] else "N/A",
            "country": r[10] if r[10] else "N/A"
        }
        for r in rows
    ]

    return render_template("logs.html", table_data=safe_rows)

@app.route("/api/logs")
def api_logs():
    if not session.get("admin"):
        return jsonify({"error": "auth required"}), 401

    rows = fetch_hits()
    out = [
        {
            "id": r[0], "doc_ref": r[1], "user_id": r[2],
            "ip": r[3], "ua": r[4], "ts": r[5],
            "lat": r[6], "lon": r[7], "city": r[8],
            "region": r[9], "country": r[10]
        }
        for r in rows
    ]
    return jsonify(out)

# ======================================================
# ------------- Run App --------------------------------
# ======================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
