import os
import base64
import hashlib
import hmac
import uuid
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, request, redirect, render_template, abort, send_file, jsonify, make_response
from flask_socketio import SocketIO, join_room, emit
from werkzeug.utils import secure_filename

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "diskord.db")
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_MB = 10
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES
app.secret_key = os.environ.get("DISKORD_SECRET", "CHANGE_ME")

socketio = SocketIO(app, cors_allowed_origins=[], async_mode="eventlet")  # same-origin

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pw_salt TEXT NOT NULL,
      pw_hash TEXT NOT NULL,
      pubkey_jwk TEXT,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS friend_requests(
      id TEXT PRIMARY KEY,
      from_id TEXT NOT NULL,
      to_id TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS conversations(
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      name TEXT,
      owner_id TEXT,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS conversation_members(
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS conversation_keys(
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      wrapped_key TEXT NOT NULL,
      nonce TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages(
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL,
      created_at TEXT NOT NULL,
      attachment_id TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files(
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      path TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    con.commit()
    con.close()

init_db()

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()

def hash_password(pw: str, salt_b64: str) -> str:
    return sha256_hex(b64d(salt_b64) + pw.encode("utf-8"))

def new_token() -> str:
    return b64e(os.urandom(32))

def current_user():
    tok = request.cookies.get("diskord_session")
    if not tok:
        return None
    con = db()
    try:
        row = con.execute("SELECT user_id FROM sessions WHERE token=?", (tok,)).fetchone()
        if not row:
            return None
        u = con.execute("SELECT id, username, pubkey_jwk FROM users WHERE id=?", (row["user_id"],)).fetchone()
        return u
    finally:
        con.close()

def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        u = current_user()
        if not u:
            return redirect("/login")
        return fn(u, *args, **kwargs)
    return wrap

def require_member(con, convo_id: str, user_id: str) -> bool:
    r = con.execute("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?",
                    (convo_id, user_id)).fetchone()
    return bool(r)

def dm_conversation_id(con, a: str, b: str):
    rows = con.execute("""
      SELECT c.id FROM conversations c
      JOIN conversation_members m1 ON m1.conversation_id=c.id AND m1.user_id=?
      JOIN conversation_members m2 ON m2.conversation_id=c.id AND m2.user_id=?
      WHERE c.type='dm'
    """, (a, b)).fetchall()
    return rows[0]["id"] if rows else None

def accepted_friend_ids(con, user_id: str):
    rows = con.execute("""
      SELECT from_id, to_id, status FROM friend_requests
      WHERE status='accepted' AND (from_id=? OR to_id=?)
    """, (user_id, user_id)).fetchall()
    out=set()
    for r in rows:
        other = r["to_id"] if r["from_id"]==user_id else r["from_id"]
        out.add(other)
    return out

@app.get("/")
def index():
    if current_user():
        return redirect("/app")
    return redirect("/login")

@app.get("/privacy")
def privacy():
    return render_template("privacy.html")

@app.get("/register")
def register_page():
    return render_template("register.html", slogan="A Discord alternative that values your privacy")

@app.post("/register")
def register_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username or not password:
        return render_template("register.html", error="Missing username or password.", slogan="A Discord alternative that values your privacy"), 400
    if len(password) < 6:
        return render_template("register.html", error="Password too short.", slogan="A Discord alternative that values your privacy"), 400

    uid = str(uuid.uuid4())
    salt = b64e(os.urandom(16))
    pwh = hash_password(password, salt)

    con = db()
    try:
        con.execute("INSERT INTO users(id, username, pw_salt, pw_hash, created_at) VALUES(?,?,?,?,?)",
                    (uid, username, salt, pwh, now_iso()))
        con.commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", error="Username already taken.", slogan="A Discord alternative that values your privacy"), 400
    finally:
        con.close()

    return redirect("/login")

@app.get("/login")
def login_page():
    return render_template("login.html", slogan="A Discord alternative that values your privacy")

@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    con = db()
    try:
        u = con.execute("SELECT id, pw_salt, pw_hash FROM users WHERE username=?", (username,)).fetchone()
        if not u:
            return render_template("login.html", error="Invalid credentials.", slogan="A Discord alternative that values your privacy"), 401
        calc = hash_password(password, u["pw_salt"])
        if not hmac.compare_digest(calc, u["pw_hash"]):
            return render_template("login.html", error="Invalid credentials.", slogan="A Discord alternative that values your privacy"), 401

        tok = new_token()
        con.execute("INSERT INTO sessions(token, user_id, created_at) VALUES(?,?,?)", (tok, u["id"], now_iso()))
        con.commit()
    finally:
        con.close()

    resp = make_response(redirect("/app"))
    resp.set_cookie("diskord_session", tok, httponly=True, samesite="Lax", secure=False)
    return resp

@app.post("/logout")
def logout():
    tok = request.cookies.get("diskord_session")
    if tok:
        con=db()
        try:
            con.execute("DELETE FROM sessions WHERE token=?", (tok,))
            con.commit()
        finally:
            con.close()
    resp = make_response(redirect("/login"))
    resp.delete_cookie("diskord_session")
    return resp

@app.get("/app")
@login_required
def app_page(user):
    con = db()
    uid = user["id"]
    try:
        pending = con.execute("""
          SELECT fr.id, u.username AS from_username FROM friend_requests fr
          JOIN users u ON u.id=fr.from_id
          WHERE fr.to_id=? AND fr.status='pending'
          ORDER BY fr.created_at DESC
        """, (uid,)).fetchall()

        friends = []
        for fid in sorted(list(accepted_friend_ids(con, uid))):
            ru = con.execute("SELECT id, username FROM users WHERE id=?", (fid,)).fetchone()
            if ru:
                friends.append({"id": ru["id"], "username": ru["username"]})

        convos = con.execute("""
          SELECT c.id, c.type, c.name, c.owner_id
          FROM conversations c
          JOIN conversation_members m ON m.conversation_id=c.id
          WHERE m.user_id=?
          ORDER BY c.created_at DESC
        """, (uid,)).fetchall()

        convo_list=[]
        for c in convos:
            name = c["name"]
            if c["type"]=="dm":
                other = con.execute("""
                  SELECT u.username FROM conversation_members m
                  JOIN users u ON u.id=m.user_id
                  WHERE m.conversation_id=? AND m.user_id!=?
                """, (c["id"], uid)).fetchone()
                name = other["username"] if other else "DM"
            else:
                name = name or "Group"
            convo_list.append({"id": c["id"], "type": c["type"], "name": name, "owner_id": c["owner_id"]})

        selected = convo_list[0]["id"] if convo_list else None

        msgs=[]
        if selected:
            rows = con.execute("""
              SELECT m.id, m.ciphertext, m.nonce, m.created_at, u.username, m.attachment_id
              FROM messages m
              JOIN users u ON u.id=m.user_id
              WHERE m.conversation_id=?
              ORDER BY m.created_at ASC
              LIMIT 200
            """, (selected,)).fetchall()
            for r in rows:
                msgs.append({
                    "id": r["id"],
                    "username": r["username"],
                    "ciphertext": r["ciphertext"],
                    "nonce": r["nonce"],
                    "created_at": r["created_at"],
                    "attachment_id": r["attachment_id"]
                })

        return render_template(
            "app.html",
            username=user["username"],
            user_id=uid,
            convos=convo_list,
            selected_id=selected,
            pending=[{"id": p["id"], "from_username": p["from_username"]} for p in pending],
            friends=friends,
            initial_messages=msgs,
        )
    finally:
        con.close()

@app.get("/api/me/pubkey")
@login_required
def api_me_pubkey(user):
    return jsonify({"pubkey_jwk": user["pubkey_jwk"]})

@app.post("/api/me/pubkey")
@login_required
def api_set_pubkey(user):
    data = request.get_json(silent=True) or {}
    jwk = data.get("pubkey_jwk")
    if not jwk or len(jwk) > 8000:
        abort(400)
    con=db()
    try:
        con.execute("UPDATE users SET pubkey_jwk=? WHERE id=?", (jwk, user["id"]))
        con.commit()
    finally:
        con.close()
    return jsonify({"ok": True})

@app.get("/api/users/by-username")
@login_required
def api_user_by_username(user):
    q=(request.args.get("q") or "").strip()
    if not q:
        return jsonify({"user": None})
    con=db()
    try:
        u=con.execute("SELECT id, username, pubkey_jwk FROM users WHERE username=?", (q,)).fetchone()
        if not u:
            return jsonify({"user": None})
        return jsonify({"user": {"id": u["id"], "username": u["username"], "pubkey_jwk": u["pubkey_jwk"]}})
    finally:
        con.close()

@app.get("/api/conversations/<convo_id>/messages")
@login_required
def api_messages(user, convo_id):
    con=db()
    try:
        if not require_member(con, convo_id, user["id"]):
            abort(403)
        rows = con.execute("""
          SELECT m.id, m.ciphertext, m.nonce, m.created_at, u.username, m.attachment_id
          FROM messages m JOIN users u ON u.id=m.user_id
          WHERE m.conversation_id=?
          ORDER BY m.created_at ASC
          LIMIT 500
        """, (convo_id,)).fetchall()
        msgs=[]
        for r in rows:
            msgs.append({
                "id": r["id"],
                "username": r["username"],
                "ciphertext": r["ciphertext"],
                "nonce": r["nonce"],
                "created_at": r["created_at"],
                "attachment_id": r["attachment_id"]
            })
        return jsonify(msgs)
    finally:
        con.close()


@app.get("/api/conversations/<convo_id>/members")
@login_required
def api_members(user, convo_id):
    con = db()
    try:
        if not require_member(con, convo_id, user["id"]):
            abort(403)
        convo = con.execute("SELECT id, type, owner_id FROM conversations WHERE id=?", (convo_id,)).fetchone()
        if not convo:
            abort(404)
        rows = con.execute("""
          SELECT u.id, u.username
          FROM conversation_members m
          JOIN users u ON u.id=m.user_id
          WHERE m.conversation_id=?
          ORDER BY LOWER(u.username) ASC
        """, (convo_id,)).fetchall()
        friends = accepted_friend_ids(con, user["id"])
        out = []
        for r in rows:
            out.append({
                "id": r["id"],
                "username": r["username"],
                "is_self": r["id"] == user["id"],
                "is_owner": convo["owner_id"] == r["id"] if convo["type"] == "group" else False,
                "is_friend": r["id"] in friends
            })
        return jsonify({"type": convo["type"], "owner_id": convo["owner_id"], "members": out})
    finally:
        con.close()

@app.get("/api/conversations/<convo_id>/key")
@login_required
def api_convo_key(user, convo_id):
    con=db()
    try:
        if not require_member(con, convo_id, user["id"]):
            abort(403)
        r = con.execute("""
          SELECT wrapped_key, nonce FROM conversation_keys
          WHERE conversation_id=? AND user_id=?
          ORDER BY created_at DESC LIMIT 1
        """, (convo_id, user["id"])).fetchone()
        if not r:
            return jsonify({"wrapped_key": None})
        return jsonify({"wrapped_key": r["wrapped_key"], "nonce": r["nonce"]})
    finally:
        con.close()

@app.post("/api/conversations/<convo_id>/keys")
@login_required
def api_set_convo_keys(user, convo_id):
    data = request.get_json(silent=True) or {}
    keys = data.get("keys") or []
    if not isinstance(keys, list) or len(keys) > 200:
        abort(400)
    con=db()
    try:
        if not require_member(con, convo_id, user["id"]):
            abort(403)
        convo = con.execute("SELECT type, owner_id FROM conversations WHERE id=?", (convo_id,)).fetchone()
        if not convo:
            abort(404)
        if convo["type"] == "group" and convo["owner_id"] != user["id"]:
            abort(403)

        for k in keys:
            uid = k.get("user_id")
            wk = k.get("wrapped_key")
            nn = k.get("nonce")
            if not uid or not wk or not nn:
                continue
            if not require_member(con, convo_id, uid):
                continue
            con.execute("INSERT INTO conversation_keys(id, conversation_id, user_id, wrapped_key, nonce, created_at) VALUES(?,?,?,?,?,?)",
                        (str(uuid.uuid4()), convo_id, uid, wk, nn, now_iso()))
        con.commit()
    finally:
        con.close()
    return jsonify({"ok": True})

@app.post("/friends/request")
@login_required
def friends_request(user):
    target = (request.form.get("username") or "").strip()
    if not target:
        return redirect("/app")
    con=db()
    try:
        t = con.execute("SELECT id FROM users WHERE username=?", (target,)).fetchone()
        if not t or t["id"] == user["id"]:
            return redirect("/app")
        existing = con.execute("""
          SELECT 1 FROM friend_requests
          WHERE ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?))
          AND status IN ('pending','accepted')
        """, (user["id"], t["id"], t["id"], user["id"])).fetchone()
        if existing:
            return redirect("/app")
        fr_id=str(uuid.uuid4())
        con.execute("INSERT INTO friend_requests(id, from_id, to_id, status, created_at) VALUES(?,?,?,?,?)",
                    (fr_id, user["id"], t["id"], "pending", now_iso()))
        con.commit()
        socketio.emit("friend_request", {"id": fr_id, "from_username": user["username"]}, room=f"user:{t['id']}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/friends/accept")
@login_required
def friends_accept(user):
    req_id = request.form.get("req_id") or ""
    con=db()
    try:
        fr = con.execute("SELECT * FROM friend_requests WHERE id=?", (req_id,)).fetchone()
        if not fr or fr["to_id"] != user["id"] or fr["status"] != "pending":
            return redirect("/app")
        con.execute("UPDATE friend_requests SET status='accepted' WHERE id=?", (req_id,))
        con.commit()
        socketio.emit("friend_accept", {}, room=f"user:{fr['from_id']}")
        socketio.emit("friend_accept", {}, room=f"user:{user['id']}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/friends/ignore")
@login_required
def friends_ignore(user):
    req_id = request.form.get("req_id") or ""
    con=db()
    try:
        fr = con.execute("SELECT * FROM friend_requests WHERE id=?", (req_id,)).fetchone()
        if fr and fr["to_id"] == user["id"] and fr["status"] == "pending":
            con.execute("DELETE FROM friend_requests WHERE id=?", (req_id,))
            con.commit()
            socketio.emit("friend_ignore", {"id": req_id}, room=f"user:{user['id']}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/friends/remove")
@login_required
def friends_remove(user):
    fid = request.form.get("friend_id") or ""
    if not fid:
        return redirect("/app")
    con=db()
    try:
        con.execute("""
          DELETE FROM friend_requests
          WHERE status='accepted' AND ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?))
        """, (user["id"], fid, fid, user["id"]))
        con.commit()
        socketio.emit("friend_remove", {"id": fid}, room=f"user:{user['id']}")
        socketio.emit("friend_remove", {"id": user["id"]}, room=f"user:{fid}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/dm/start")
@login_required
def dm_start(user):
    fid = request.form.get("friend_id") or ""
    con=db()
    try:
        if fid not in accepted_friend_ids(con, user["id"]):
            abort(403)
        cid = dm_conversation_id(con, user["id"], fid)
        if not cid:
            cid = str(uuid.uuid4())
            con.execute("INSERT INTO conversations(id, type, name, owner_id, created_at) VALUES(?,?,?,?,?)",
                        (cid, "dm", None, None, now_iso()))
            con.execute("INSERT INTO conversation_members(id, conversation_id, user_id, created_at) VALUES(?,?,?,?)",
                        (str(uuid.uuid4()), cid, user["id"], now_iso()))
            con.execute("INSERT INTO conversation_members(id, conversation_id, user_id, created_at) VALUES(?,?,?,?)",
                        (str(uuid.uuid4()), cid, fid, now_iso()))
            con.commit()
        return redirect("/app")
    finally:
        con.close()

@app.post("/groups/create")
@login_required
def groups_create(user):
    name = (request.form.get("name") or "").strip()[:60]
    member_ids = [x.strip() for x in (request.form.get("member_ids") or "").split(",") if x.strip()]
    con=db()
    try:
        allowed = accepted_friend_ids(con, user["id"])
        selected = [mid for mid in member_ids if mid in allowed]
        cid=str(uuid.uuid4())
        con.execute("INSERT INTO conversations(id, type, name, owner_id, created_at) VALUES(?,?,?,?,?)",
                    (cid, "group", name or "Group", user["id"], now_iso()))
        for uid in set(selected + [user["id"]]):
            con.execute("INSERT INTO conversation_members(id, conversation_id, user_id, created_at) VALUES(?,?,?,?)",
                        (str(uuid.uuid4()), cid, uid, now_iso()))
        con.commit()
        for uid in set(selected):
            socketio.emit("group_joined", {"conversation_id": cid, "name": name or "Group"}, room=f"user:{uid}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/groups/invite")
@login_required
def groups_invite(user):
    convo_id = request.form.get("conversation_id") or ""
    member_ids = [x.strip() for x in (request.form.get("member_ids") or "").split(",") if x.strip()]
    con=db()
    try:
        convo = con.execute("SELECT * FROM conversations WHERE id=?", (convo_id,)).fetchone()
        if not convo or convo["type"] != "group":
            abort(404)
        if not require_member(con, convo_id, user["id"]):
            abort(403)
        allowed = accepted_friend_ids(con, user["id"])
        selected = [mid for mid in member_ids if mid in allowed]
        for uid in set(selected):
            if require_member(con, convo_id, uid):
                continue
            con.execute("INSERT INTO conversation_members(id, conversation_id, user_id, created_at) VALUES(?,?,?,?)",
                        (str(uuid.uuid4()), convo_id, uid, now_iso()))
            socketio.emit("group_joined", {"conversation_id": convo_id, "name": convo["name"]}, room=f"user:{uid}")
            socketio.emit("group_member_join", {"conversation_id": convo_id, "user_id": uid}, room=f"convo:{convo_id}")
        con.commit()
    finally:
        con.close()
    return redirect("/app")

@app.post("/groups/leave")
@login_required
def groups_leave(user):
    convo_id = request.form.get("conversation_id") or ""
    con=db()
    try:
        convo = con.execute("SELECT * FROM conversations WHERE id=?", (convo_id,)).fetchone()
        if not convo or convo["type"] != "group":
            abort(404)
        if not require_member(con, convo_id, user["id"]):
            abort(403)
        con.execute("DELETE FROM conversation_members WHERE conversation_id=? AND user_id=?", (convo_id, user["id"]))
        con.commit()
        socketio.emit("group_left", {"conversation_id": convo_id, "user_id": user["id"]}, room=f"convo:{convo_id}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/groups/kick")
@login_required
def groups_kick(user):
    convo_id = request.form.get("conversation_id") or ""
    target_id = request.form.get("user_id") or ""
    con=db()
    try:
        convo = con.execute("SELECT * FROM conversations WHERE id=?", (convo_id,)).fetchone()
        if not convo or convo["type"] != "group":
            abort(404)
        if convo["owner_id"] != user["id"]:
            abort(403)
        if target_id == user["id"]:
            return redirect("/app")
        if require_member(con, convo_id, target_id):
            con.execute("DELETE FROM conversation_members WHERE conversation_id=? AND user_id=?", (convo_id, target_id))
            con.commit()
            socketio.emit("group_kicked", {"conversation_id": convo_id}, room=f"user:{target_id}")
            socketio.emit("group_left", {"conversation_id": convo_id, "user_id": target_id}, room=f"convo:{convo_id}")
    finally:
        con.close()
    return redirect("/app")

@app.post("/upload")
@login_required
def upload(user):
    convo_id = request.form.get("conversation_id") or ""
    con=db()
    try:
        if not convo_id or not require_member(con, convo_id, user["id"]):
            abort(403)
        f = request.files.get("file")
        if not f or not f.filename:
            abort(400)
        filename = secure_filename(f.filename)[:180] or "file"
        mime = (request.form.get("mime") or f.mimetype or "application/octet-stream")[:120]
        if request.content_length and request.content_length > MAX_FILE_BYTES:
            abort(413)
        fid=str(uuid.uuid4())
        path=os.path.join(UPLOAD_DIR, fid)
        f.save(path)
        con.execute("INSERT INTO files(id, conversation_id, user_id, filename, mime, size, path, created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (fid, convo_id, user["id"], filename, mime, os.path.getsize(path), path, now_iso()))
        con.commit()
        return jsonify({"ok": True, "file_id": fid, "filename": filename})
    finally:
        con.close()

@app.get("/files/<file_id>")
@login_required
def get_file(user, file_id):
    con=db()
    try:
        r=con.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not r:
            abort(404)
        if not require_member(con, r["conversation_id"], user["id"]):
            abort(403)
        return send_file(r["path"], as_attachment=True, download_name=r["filename"], mimetype="application/octet-stream")
    finally:
        con.close()

@socketio.on("connect")
def sio_connect(auth):
    con=db()
    try:
        tok = request.cookies.get("diskord_session")
        if not tok:
            return False
        s = con.execute("SELECT user_id FROM sessions WHERE token=?", (tok,)).fetchone()
        if not s:
            return False
        uid=s["user_id"]
        join_room(f"user:{uid}")
        emit("connected", {"ok": True})
    finally:
        con.close()

@socketio.on("convo_join")
def sio_join(data):
    convo_id = (data or {}).get("conversationId")
    if not convo_id:
        return
    con=db()
    try:
        tok=request.cookies.get("diskord_session")
        s=con.execute("SELECT user_id FROM sessions WHERE token=?", (tok,)).fetchone()
        if not s:
            return
        uid=s["user_id"]
        if not require_member(con, convo_id, uid):
            return
        join_room(f"convo:{convo_id}")
        emit("joined", {"conversationId": convo_id})
    finally:
        con.close()

@socketio.on("message_send")
def sio_send(data):
    convo_id=(data or {}).get("conversationId")
    ciphertext=(data or {}).get("ciphertext")
    nonce=(data or {}).get("nonce")
    attachment_id=(data or {}).get("attachment_id")
    if not convo_id or not ciphertext or not nonce:
        return
    con=db()
    try:
        tok=request.cookies.get("diskord_session")
        s=con.execute("SELECT user_id FROM sessions WHERE token=?", (tok,)).fetchone()
        if not s:
            return
        uid=s["user_id"]
        if not require_member(con, convo_id, uid):
            return
        mid=str(uuid.uuid4())
        con.execute("INSERT INTO messages(id, conversation_id, user_id, ciphertext, nonce, created_at, attachment_id) VALUES(?,?,?,?,?,?,?)",
                    (mid, convo_id, uid, ciphertext, nonce, now_iso(), attachment_id))
        con.commit()
        uname = con.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()["username"]
        emit("message_new", {
            "id": mid,
            "conversationId": convo_id,
            "user": {"id": uid, "username": uname},
            "ciphertext": ciphertext,
            "nonce": nonce,
            "createdAt": now_iso(),
            "attachment_id": attachment_id
        }, room=f"convo:{convo_id}")
    finally:
        con.close()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=4000, debug=True)
