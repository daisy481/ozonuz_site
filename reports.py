"""
OzonUz — murojaatlar API (Vercel Python serverless funksiya, Postgres).

  GET   /api/reports            -> ommaviy ro'yxat (faqat checked/sent/solved).
                                   Authorization: Bearer ADMIN_TOKEN bo'lsa — hammasi (rasmlar ichida).
  GET   /api/reports?photo=ID   -> rasm (faqat ommaviy holatdagilar; admin uchun hammasi)
  POST  /api/reports            -> yangi murojaat (sayt formasi — tokensiz; bot — Bearer BOT_API_TOKEN)
  PATCH /api/reports            -> {"id":12,"status":"checked"} — faqat ADMIN_TOKEN

Muhit o'zgaruvchilari (Vercel -> Settings -> Environment Variables):
  DATABASE_URL (yoki POSTGRES_URL) — Storage'dan Postgres ulanganda avtomatik qo'shiladi
  ADMIN_TOKEN    — moderator/admin uchun uzun maxfiy so'z
  BOT_API_TOKEN  — Telegram bot uchun uzun maxfiy so'z (bot.py dagi API_TOKEN bilan bir xil)
"""
import base64
import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import psycopg2
import psycopg2.extras

DSN = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or ""
ADMIN = os.environ.get("ADMIN_TOKEN", "")
BOT = os.environ.get("BOT_API_TOKEN", "")
SALT = os.environ.get("IP_SALT") or ADMIN or "ozonuz"

TYPES = {"ref", "fridge", "other"}
STATUSES = {"new", "checked", "sent", "solved", "rejected"}
PUBLIC = ("checked", "sent", "solved")
LAT = (37.1, 45.7)          # O'zbekiston chegaralari (taxminiy to'rtburchak)
LON = (55.9, 73.2)
MAX_BODY = 400_000
MAX_PHOTO = 100_000         # data-URL uzunligi (420 px JPEG ~ 30-55 ming belgi)
ADMIN_LIST_LIMIT = 40       # rasmlar ichida: javob hajmi Vercel 4.5 MB limitidan oshmasin
PUBLIC_LIST_LIMIT = 300
ANON_PER_HOUR = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports(
  id BIGSERIAL PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('ref','fridge','other')),
  text TEXT NOT NULL,
  lat DOUBLE PRECISION NOT NULL,
  lon DOUBLE PRECISION NOT NULL,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','checked','sent','solved','rejected')),
  source TEXT NOT NULL DEFAULT 'web',
  photo TEXT NOT NULL DEFAULT '',
  client_id TEXT UNIQUE,
  tg_chat_id BIGINT,
  ip_hash TEXT,
  created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_created_idx ON reports(created DESC);
CREATE INDEX IF NOT EXISTS reports_ip_idx ON reports(ip_hash, created);
"""
_schema_ready = False


def db():
    global _schema_ready
    conn = psycopg2.connect(DSN, connect_timeout=5)
    if not _schema_ready:
        with conn, conn.cursor() as cur:
            cur.execute(SCHEMA)
        _schema_ready = True
    return conn


@contextmanager
def cursor(dict_rows=False):
    """Ulanish har so'rovda ochiladi va yopiladi; with tugasa commit (xato bo'lsa rollback)."""
    conn = db()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor if dict_rows else None) as cur:
                yield cur
    finally:
        conn.close()


def _eq(a: str, b: str) -> bool:
    return bool(b) and hmac.compare_digest(a.encode(), b.encode())


def public_row(r, inline_photo=False):
    photo = ""
    if r["photo"]:
        photo = r["photo"] if inline_photo else f"/api/reports?photo={r['id']}"
    return {"id": str(r["id"]), "type": r["type"], "text": r["text"], "lat": r["lat"], "lon": r["lon"],
            "status": r["status"], "source": r["source"], "created": r["created"], "photo": photo}


class handler(BaseHTTPRequestHandler):
    # ---------------------------------------------------------- yordamchilar
    def _send(self, code, obj=None, raw=None, ctype="application/json; charset=utf-8", cache="no-store"):
        body = raw if raw is not None else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, msg):
        self._send(code, {"error": msg})

    def _role(self):
        h = self.headers.get("Authorization", "")
        if not h:
            return "anon"
        tok = h[7:].strip() if h.lower().startswith("bearer ") else ""
        if _eq(tok, ADMIN):
            return "admin"
        if _eq(tok, BOT):
            return "bot"
        return "bad"

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return None
        try:
            d = json.loads(self.rfile.read(n))
            return d if isinstance(d, dict) else None
        except ValueError:
            return None

    def _ip_hash(self):
        ip = (self.headers.get("x-forwarded-for", "").split(",")[0].strip()
              or self.headers.get("x-real-ip", "") or self.client_address[0])
        return hashlib.sha256((SALT + ip).encode()).hexdigest()[:32]

    # ------------------------------------------------------------------- GET
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        role = self._role()
        if role == "bad":
            return self._err(401, "bad_token")
        try:
            with cursor(dict_rows=True) as cur:
                if "photo" in q:
                    return self._photo(cur, q["photo"][0], role == "admin")
                if role == "admin":
                    cur.execute("SELECT * FROM reports ORDER BY (status='new') DESC, created DESC LIMIT %s",
                                (ADMIN_LIST_LIMIT,))
                    rows = [public_row(r, inline_photo=True) for r in cur.fetchall()]
                    return self._send(200, {"role": "admin", "reports": rows})
                cur.execute("SELECT * FROM reports WHERE status = ANY(%s) ORDER BY created DESC LIMIT %s",
                            (list(PUBLIC), PUBLIC_LIST_LIMIT))
                rows = [public_row(r) for r in cur.fetchall()]
                return self._send(200, {"role": "public", "reports": rows})
        except Exception as e:
            print("GET error:", repr(e))
            return self._err(500, "server_error")

    def _photo(self, cur, rid, is_admin):
        if not rid.isdigit():
            return self._err(404, "not_found")
        cur.execute("SELECT photo, status FROM reports WHERE id=%s", (int(rid),))
        r = cur.fetchone()
        if not r or not r["photo"] or (not is_admin and r["status"] not in PUBLIC):
            return self._err(404, "not_found")
        head, _, b64 = r["photo"].partition(",")
        ctype = head[5:].split(";")[0] or "image/jpeg"
        return self._send(200, raw=base64.b64decode(b64), ctype=ctype,
                          cache="public, max-age=86400" if r["status"] in PUBLIC else "private, no-store")

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        role = self._role()
        if role == "bad":
            return self._err(401, "bad_token")
        d = self._json_body()
        if d is None:
            return self._err(400, "bad_json")
        kind = d.get("type")
        text = str(d.get("text", "")).strip()[:600]
        try:
            lat, lon = float(d.get("lat")), float(d.get("lon"))
        except (TypeError, ValueError):
            return self._err(422, "bad_location")
        photo = d.get("photo") or ""
        if kind not in TYPES:
            return self._err(422, "bad_type")
        if not text:
            return self._err(422, "empty_text")
        if not (LAT[0] <= lat <= LAT[1] and LON[0] <= lon <= LON[1]):
            return self._err(422, "outside_uz")
        if photo and (not isinstance(photo, str) or len(photo) > MAX_PHOTO
                      or not photo.startswith(("data:image/jpeg;base64,", "data:image/png;base64,"))):
            return self._err(422, "bad_photo")
        now = int(time.time() * 1000)
        created = d.get("created")
        if not (isinstance(created, int) and now - 30 * 86400_000 <= created <= now + 300_000):
            created = now
        cid = str(d["client_id"])[:64] if d.get("client_id") else None
        is_bot = role == "bot"
        tg = d.get("tg_chat_id") if is_bot and isinstance(d.get("tg_chat_id"), int) else None
        iph = self._ip_hash()
        try:
            with cursor() as cur:
                if not is_bot:      # tokensiz (sayt formasi) — soatiga 10 ta
                    cur.execute("SELECT count(*) FROM reports WHERE ip_hash=%s AND created>%s", (iph, now - 3600_000))
                    if cur.fetchone()[0] >= ANON_PER_HOUR:
                        out = (429, {"error": "too_many"})
                    else:
                        out = None
                else:
                    out = None
                if out is None:
                    cur.execute(
                        """INSERT INTO reports(type,text,lat,lon,source,photo,client_id,tg_chat_id,ip_hash,created)
                           VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                           ON CONFLICT (client_id) DO NOTHING RETURNING id""",
                        (kind, text, round(lat, 5), round(lon, 5), "bot" if is_bot else "web", photo, cid, tg,
                         iph, created))
                    row = cur.fetchone()
                    if row:
                        out = (201, {"ok": True, "id": str(row[0])})
                    else:
                        cur.execute("SELECT id FROM reports WHERE client_id=%s", (cid,))
                        out = (200, {"ok": True, "id": str(cur.fetchone()[0]), "duplicate": True})
            return self._send(*out)      # javob commit'dan keyin yuboriladi
        except Exception as e:
            print("POST error:", repr(e))
            return self._err(500, "server_error")

    # ----------------------------------------------------------------- PATCH
    def do_PATCH(self):
        if self._role() != "admin":
            return self._err(401, "admin_only")
        d = self._json_body()
        if d is None or d.get("status") not in STATUSES or not str(d.get("id", "")).isdigit():
            return self._err(422, "bad_request")
        try:
            with cursor() as cur:
                cur.execute("UPDATE reports SET status=%s WHERE id=%s RETURNING id", (d["status"], int(d["id"])))
                found = cur.fetchone() is not None
            return self._send(200, {"ok": True}) if found else self._err(404, "not_found")
        except Exception as e:
            print("PATCH error:", repr(e))
            return self._err(500, "server_error")

    def log_message(self, *a):      # Vercel jurnalini ortiqcha to'ldirmaslik uchun
        pass
