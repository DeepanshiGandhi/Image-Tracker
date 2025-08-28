import os
import sqlite3
import datetime
import shortuuid
from flask import Flask, render_template, request, send_file, jsonify, Response, redirect, url_for
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

app = Flask(__name__)
DB_FILE = "logs.db"

# ============================
# Database Setup
# ============================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user_agent TEXT,
            time TEXT
        )"""
    )
    conn.commit()
    conn.close()

def log_request(ip, ua):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO logs (ip, user_agent, time) VALUES (?, ?, ?)",
                (ip, ua, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

# ============================
# Routes
# ============================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file uploaded", 400
        f = request.files["file"]
        if f.filename == "":
            return "No file selected", 400

        file_ext = os.path.splitext(f.filename)[1].lower()
        uid = shortuuid.uuid()
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, uid + file_ext)
        f.save(filepath)

        tracking_url = request.url_root.strip("/") + url_for("track", uid=uid)

        # ============================
        # PNG with tracking pixel
        # ============================
        if file_ext == ".png":
            img = Image.open(filepath).convert("RGBA")
            px = Image.new("RGBA", (1, 1), (255, 255, 255, 0))
            img.paste(px, (0, 0))
            outpath = os.path.join(upload_dir, uid + "_tracked.png")
            img.save(outpath, "PNG")
            return send_file(outpath, as_attachment=True)

        # ============================
        # SVG with embedded pixel
        # ============================
        elif file_ext == ".svg":
            with open(filepath, "r", encoding="utf-8") as svg:
                content = svg.read()
            injected = content.replace(
                "</svg>",
                f'<image href="{tracking_url}" width="1" height="1" />\n</svg>'
            )
            outpath = os.path.join(upload_dir, uid + "_tracked.svg")
            with open(outpath, "w", encoding="utf-8") as outf:
                outf.write(injected)
            return send_file(outpath, as_attachment=True)

        # ============================
        # PDF with external tracking reference
        # ============================
        elif file_ext == ".pdf" or file_ext in [".jpg", ".jpeg"]:
            outpath = os.path.join(upload_dir, uid + "_tracked.pdf")
            create_pdf_with_pixel(filepath, outpath, letter, tracking_url)
            return send_file(outpath, as_attachment=True)

        else:
            return "Unsupported file type", 400

    return render_template("upload.html")

@app.route("/track/<uid>")
def track(uid):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent")
    log_request(ip, ua)

    # 1x1 transparent pixel
    pixel = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00" \
            b"\x00\x00\x00\xFF\xFF\xFF!\xF9\x04\x01\x00\x00\x00\x00" \
            b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"
    return Response(pixel, mimetype="image/gif")

@app.route("/logs")
def logs():
    rows = get_logs()
    return render_template("logs.html", logs=rows)

# ============================
# PDF Generation
# ============================
def create_pdf_with_pixel(image_path: str, pdf_path: str, page_size=letter, tracking_url: str = None):
    c = canvas.Canvas(pdf_path, pagesize=page_size)
    width, height = page_size

    # If it's a JPEG/PNG, draw it
    if image_path.lower().endswith((".jpg", ".jpeg", ".png")):
        try:
            img = ImageReader(image_path)
            iw, ih = img.getSize()
            margin = 36
            max_w, max_h = width - 2*margin, height - 2*margin
            scale = min(max_w / iw, max_h / ih)
            dw, dh = iw * scale, ih * scale
            x = (width - dw) / 2
            y = (height - dh) / 2
            c.drawImage(img, x, y, dw, dh, preserveAspectRatio=True, mask='auto')
        except Exception:
            pass

    # Inject external tracking image reference
    if tracking_url:
        c.saveState()
        # Raw PDF operator injection: tell viewer to fetch external image
        c._code.append(
            f"q 1 0 0 1 1 1 cm /ImgDo Do Q\n"
            f"/ImgDo << /Type /XObject /Subtype /Image "
            f"/Width 1 /Height 1 /ColorSpace /DeviceRGB "
            f"/BitsPerComponent 8 /Filter /DCTDecode "
            f"/F ({tracking_url}) >> def\n"
        )
        c.restoreState()

    c.showPage()
    c.save()

# ============================
# Main
# ============================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
