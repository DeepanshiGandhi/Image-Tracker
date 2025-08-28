import os
import sqlite3
import datetime
import hashlib
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, Response, jsonify
)
from PIL import Image
import shortuuid
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

# ---------------- CONFIG ----------------
APP_SECRET = os.environ.get("SECRET_KEY", "dev_secret_change_this")
DB_FILE = "hits.db"
OUTDIR = "generated"
os.makedirs(OUTDIR, exist_ok=True)

ADMIN_ID = "admin"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "admin123")

app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET

# Rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per day", "200 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0
    )''')
    # Hits table
    c.execute('''CREATE TABLE IF NOT EXISTS hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        track_id TEXT,
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
    conn.commit()
    conn.close()

    # Ensure admin exists
    hashed_admin = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, 1)",
              (ADMIN_ID, hashed_admin))
    conn.commit()
    conn.close()

init_db()

# ---------------- GEOLOCATION ----------------
def geo_ip(ip):
    """Fallback using ip-api.com"""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,lat,lon,city,regionName,country", timeout=4)
        j = r.json()
        if j.get("status") == "success":
            return j.get("lat"), j.get("lon"), j.get("city"), j.get("regionName"), j.get("country")
    except:
        pass
    return None, None, None, None, None

# ---------------- HITS ----------------
def insert_hit(track_id, user_id, ip, ua, lat=None, lon=None, city=None, region=None, country=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT INTO hits (track_id, user_id, ip, ua, ts, lat, lon, city, region, country)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (track_id, user_id, ip, ua, datetime.datetime.utcnow().isoformat() + "Z",
               lat, lon, city, region, country))
    conn.commit()
    conn.close()

def fetch_hits(limit=1000, user_id=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if user_id:
        c.execute('''SELECT id, track_id, user_id, ip, ua, ts, lat, lon, city, region, country
                      FROM hits WHERE user_id=? ORDER BY id DESC LIMIT ?''', (user_id, limit))
    else:
        c.execute('''SELECT id, track_id, user_id, ip, ua, ts, lat, lon, city, region, country
                      FROM hits ORDER BY id DESC LIMIT ?''', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------------- PDF ----------------
def create_pdf_with_pixel(image_path, pdf_path, page_size=letter, tracking_url=None):
    c = canvas.Canvas(pdf_path, pagesize=page_size)
    width, height = page_size

    img = ImageReader(image_path)
    iw, ih = img.getSize()
    margin = 36
    scale = min((width - 2*margin)/iw, (height - 2*margin)/ih)
    c.drawImage(img, (width - iw*scale)/2, (height - ih*scale)/2, iw*scale, ih*scale, preserveAspectRatio=True, mask='auto')

    if tracking_url:
        try:
            pixel = ImageReader(tracking_url)
            c.drawImage(pixel, 1, 1, 1, 1, mask='auto')
        except:
            pass
    c.showPage()
    c.save()

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("index.html")

# ----- REGISTER -----
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not password or not confirm:
            flash("All fields required", "error")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        hashed = hashlib.sha256(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (username, hashed))
            conn.commit()
            conn.close()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "error")
            return redirect(url_for("register"))

    return render_template("register.html")

# ----- LOGIN -----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Enter username and password", "error")
            return redirect(url_for("login"))

        hashed_input = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, is_admin FROM users WHERE username=? AND password=?", (username, hashed_input))
        user = c.fetchone()
        conn.close()

        if user:
            session["user"] = username
            session["user_id"] = user[0]
            session["admin"] = user[1] == 1
            flash("Logged in successfully!", "success")
            return redirect(url_for("make"))
        else:
            flash("Incorrect username or password", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

# ----- LOGOUT -----
@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("user_id", None)
    session.pop("admin", None)
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))

# ----- MAKE -----
@app.route("/make", methods=["GET","POST"])
def make():
    # Only authenticated users can access this page
    if "user" not in session:
        flash("You must be logged in to create a tracker.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        mode = request.form.get("mode", "png")
        file = request.files.get("image")
        base_image = None
        if file and file.filename:
            base_image = Image.open(file.stream).convert("RGBA")
        track_id = shortuuid.uuid()[:8]
        user_id = session.get("user_id", "anonymous")

        # SVG branch
        if mode == "svg":
            tracked_url = url_for("track", track_id=track_id, _external=True)
            svg = f'''<?xml version="1.0" encoding="utf-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
  <rect width="100%" height="100%" fill="#fff"/>
  <text x="10" y="20" font-size="14">Tracked SVG ID: {track_id}</text>
  <image x="0" y="0" width="1" height="1" href="{tracked_url}" />
</svg>'''
            fname = f"tracked_{track_id}.svg"
            fpath = os.path.join(OUTDIR, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(svg)

            html_name = f"wrapped_{track_id}.html"
            html_path = os.path.join(OUTDIR, html_name)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Tracked SVG {track_id}</title></head>
<body>
  <object data="{url_for('download_generated', name=fname, _external=True)}" type="image/svg+xml" width="800" height="600"></object>
  <img src="{url_for('track', track_id=track_id, _external=True)}" width="1" height="1" alt="">
</body></html>""")

            return render_template("made_file.html",
                                   track_id=track_id,
                                   wrapper_url=url_for("download_generated", name=html_name, _external=True),
                                   file_url=url_for("download_generated", name=fname, _external=True),
                                   file_kind="SVG",
                                   pdf_url=None)

        # PNG branch
        fname = f"tracked_{track_id}.png"
        fpath = os.path.join(OUTDIR, fname)
        if base_image is None:
            base_image = Image.new("RGBA", (800, 600), (255, 255, 255, 255))
        base_image.save(fpath, "PNG")

        tracked_url = url_for('proxy_image', track_id=track_id, filename=fname, _external=True)

        html_name = f"wrapped_{track_id}.html"
        html_path = os.path.join(OUTDIR, html_name)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Tracked PNG {track_id}</title></head>
<body style="margin:20px;font-family:system-ui,Segoe UI,Roboto,Arial;">
  <h3>Tracked PNG</h3>
  <img src="{tracked_url}" alt="Tracked PNG" style="max-width:100%;height:auto;border-radius:8px;border:1px solid #ddd;"/>
  <img src="{url_for('track', track_id=track_id, _external=True)}" width="1" height="1" alt="">
</body></html>""")

        pdf_name = f"wrapped_{track_id}.pdf"
        pdf_path = os.path.join(OUTDIR, pdf_name)
        js_ping_url = url_for('track', track_id=track_id, _external=True)
        create_pdf_with_pixel(fpath, pdf_path, page_size=letter, tracking_url=js_ping_url)

        return render_template("made_file.html",
                               track_id=track_id,
                               wrapper_url=url_for("download_generated", name=html_name, _external=True),
                               file_url=url_for("download_generated", name=fname, _external=True),
                               file_kind="PNG",
                               pdf_url=url_for("download_generated", name=pdf_name, _external=True),
                               dl_pdf_url=url_for("dl_pdf", track_id=track_id, pdfname=pdf_name, _external=True))

    return render_template("make.html")

@app.route("/proxy_image/<track_id>/<filename>")
def proxy_image(track_id, filename):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    ua = request.headers.get("User-Agent","")
    lat, lon, city, region, country = geo_ip(ip)
    user_id = session.get("user_id", "anonymous")
    insert_hit(track_id, user_id, ip, ua, lat, lon, city, region, country)
    fpath = os.path.join(OUTDIR, filename)
    if not os.path.exists(fpath):
        return "Not found", 404
    return send_file(fpath, mimetype="image/png")

@app.route("/track/<track_id>")
@limiter.limit("60 per minute")
def track(track_id):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    ua = request.headers.get("User-Agent","")
    lat, lon, city, region, country = geo_ip(ip)
    user_id = session.get("user_id", "anonymous")
    insert_hit(track_id, user_id, ip, ua, lat, lon, city, region, country)
    png1 = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82'
    return Response(png1, mimetype="image/png")

@app.route("/dl_pdf/<track_id>/<pdfname>")
def dl_pdf(track_id, pdfname):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    ua = request.headers.get("User-Agent","")
    lat, lon, city, region, country = geo_ip(ip)
    user_id = session.get("user_id", "anonymous")
    insert_hit(track_id, user_id, ip, ua, lat, lon, city, region, country)

    path = os.path.join(OUTDIR, pdfname)
    if not os.path.exists(path):
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=pdfname, mimetype="application/pdf")

@app.route("/download_generated/<name>")
def download_generated(name):
    path = os.path.join(OUTDIR, name)
    if not os.path.exists(path):
        return "Not found", 404
    lname = name.lower()
    if lname.endswith(".svg"):
        mt = "image/svg+xml"
    elif lname.endswith(".png"):
        mt = "image/png"
    elif lname.endswith(".html"):
        mt = "text/html"
    elif lname.endswith(".pdf"):
        mt = "application/pdf"
    else:
        mt = "application/octet-stream"
    return send_file(path, as_attachment=True, download_name=name, mimetype=mt)

@app.route("/logs")
def logs():
    # Only authenticated users can access logs
    if "user" not in session:
        flash("You must be logged in to view logs.", "error")
        return redirect(url_for("login"))
    
    # Check if the user is an admin
    if session.get("admin"):
        rows = fetch_hits()  # Admin can see all logs
    else:
        # Regular user can only see their own logs
        rows = fetch_hits(user_id=session.get("user_id"))

    safe_rows = []
    for r in rows:
        safe_rows.append({
            "id": r[0],
            "track_id": r[1],
            "user_id": r[2],
            "ip": r[3],
            "ua": r[4],
            "ts": r[5],
            "lat": float(r[6]) if r[6] is not None else "N/A",
            "lon": float(r[7]) if r[7] is not None else "N/A",
            "city": r[8] if r[8] is not None else "N/A",
            "region": r[9] if r[9] is not None else "N/A",
            "country": r[10] if r[10] is not None else "N/A"
        })

    return render_template("logs.html", table_data=safe_rows)

@app.route("/api/logs")
def api_logs():
    # Only authenticated users can access the logs API
    if "user" not in session:
        return jsonify({"error":"auth required"}), 401
    
    # Check if the user is an admin
    if session.get("admin"):
        rows = fetch_hits() # Admin gets all logs
    else:
        # Regular users only get their own logs
        rows = fetch_hits(user_id=session.get("user_id"))

    out = []
    for r in rows:
        out.append({
            "id": r[0], 
            "track_id": r[1], 
            "user_id": r[2], 
            "ip": r[3], 
            "ua": r[4], 
            "ts": r[5],
            "lat": r[6], 
            "lon": r[7], 
            "city": r[8], 
            "region": r[9], 
            "country": r[10]
        })
    return jsonify(out)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)