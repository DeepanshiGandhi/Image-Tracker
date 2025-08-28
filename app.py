import os
import sqlite3
import datetime
import json
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, jsonify, session, flash, Response
)
from PIL import Image
import shortuuid
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# PDF utils
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

# ------------- config -------------
APP_SECRET = os.environ.get("SECRET_KEY", "dev_secret_change_this")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
DB_FILE = "hits.db"
OUTDIR = "generated"
os.makedirs(OUTDIR, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = APP_SECRET

# Use memory storage for limiter (change to redis://... for production)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per day", "200 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# ------------- DB helpers -------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Add 'user_id' column to the 'hits' table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        track_id TEXT,
        user_id TEXT,  -- Added column
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

init_db()

def insert_hit(track_id, user_id, ip, ua, lat=None, lon=None, city=None, region=None, country=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Updated INSERT statement to include 'user_id'
    c.execute(
        'INSERT INTO hits (track_id, user_id, ip, ua, ts, lat, lon, city, region, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (track_id, user_id, ip, ua, datetime.datetime.utcnow().isoformat()+"Z", lat, lon, city, region, country)
    )
    conn.commit()
    conn.close()

def fetch_hits(limit=1000):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Updated SELECT statement to include 'user_id'
    c.execute('SELECT id, track_id, user_id, ip, ua, ts, lat, lon, city, region, country FROM hits ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# ------------- geolocation helper (MaxMind + fallback) -------------
try:
    import geoip2.database
    GEO_DB = geoip2.database.Reader("GeoLite2-City.mmdb")
    def geo_ip(ip):
        try:
            response = GEO_DB.city(ip)
            return (
                response.location.latitude,
                response.location.longitude,
                response.city.name,
                response.subdivisions.most_specific.name,
                response.country.name
            )
        except Exception:
            return None, None, None, None, None
except ImportError:
    GEO_DB = None
    def geo_ip(ip):
        """Fallback: use ip-api.com"""
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

# ------------- PDF helper (embed tracking PNG) -------------
def create_pdf_with_pixel(image_path: str, pdf_path: str, page_size=letter, tracking_url: str = None):
    """
    Create a one-page PDF with the given image and a hidden 1x1 tracking PNG.
    """
    c = canvas.Canvas(pdf_path, pagesize=page_size)
    width, height = page_size

    # Place user image
    img = ImageReader(image_path)
    iw, ih = img.getSize()
    margin = 36  # half inch margins
    max_w, max_h = width - 2*margin, height - 2*margin
    scale = min(max_w / iw, max_h / ih)
    draw_w, draw_h = iw * scale, ih * scale
    x = (width - draw_w) / 2
    y = (height - draw_h) / 2
    c.drawImage(img, x, y, draw_w, draw_h, preserveAspectRatio=True, mask='auto')

    # Embed tracking pixel if URL provided
    if tracking_url:
        try:
            pixel = ImageReader(tracking_url)
            c.drawImage(pixel, 1, 1, 1, 1, mask='auto')
        except Exception:
            # If we can’t fetch the URL at generation, skip it
            pass

    c.showPage()
    c.save()

# ------------- routes -------------
@app.route("/")
def index():
    return render_template("index.html", logged_in=session.get("admin", False))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if request.form.get("password","") == ADMIN_PASS:
            session["admin"] = True
            return redirect(url_for("make"))
        flash("Wrong password", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("index"))

@app.route("/make", methods=["GET","POST"])
def make():
    if not session.get("admin"):
        return redirect(url_for("login"))

    if request.method == "POST":
        mode = request.form.get("mode", "png")
        file = request.files.get("image")
        base_image = None
        if file and file.filename:
            base_image = Image.open(file.stream).convert("RGBA")
        track_id = shortuuid.uuid()[:8]

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
    if not session.get("admin"):
        return redirect(url_for("login"))

    rows = fetch_hits()  # get logs from DB

    safe_rows = []
    for r in rows:
        safe_rows.append({
            "id": r[0],
            "track_id": r[1],
            "user_id": r[2],
            "ip": r[3],
            "ua": r[4],  # user agent
            "ts": r[5],  # timestamp
            "lat": float(r[6]) if r[6] is not None else "N/A",
            "lon": float(r[7]) if r[7] is not None else "N/A",
            "city": r[8] if r[8] is not None else "N/A",
            "region": r[9] if r[9] is not None else "N/A",
            "country": r[10] if r[10] is not None else "N/A"
        })

    # Pass the Python list 'safe_rows' to the new template
    # Ensure you are rendering a template that contains the table structure.
    return render_template("logs.html", table_data=safe_rows)

@app.route("/api/logs")
def api_logs():
    if not session.get("admin"):
        return jsonify({"error":"auth required"}), 401
    rows = fetch_hits()
    out = []
    for r in rows:
        out.append({
            "id": r[0], 
            "track_id": r[1], 
            "user_id": r[2], # Added this line
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