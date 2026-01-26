import os
import secrets
import uuid
import sqlite3
import mimetypes
from flask import Flask, request, redirect, make_response, render_template, jsonify, abort, send_file
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename

from db import Base, engine, SessionLocal
from models import User, Friendship, Conversation, ConversationMember, Message
from auth import hash_password, verify_password, SessionSigner, new_csrf

from sqlalchemy import or_, and_

Base.metadata.create_all(bind=engine)


def _ensure_message_attachment_columns():
    """
    Simple SQLite migration for existing chat.db files:
    adds attachment_* columns if missing.
    """
    db_path = os.path.join(os.path.dirname(__file__), "chat.db")
    if not os.path.exists(db_path):
        return
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("PRAGMA table_info(messages)")
        cols = {row[1] for row in cur.fetchall()}
        needed = {
            "attachment_name": "TEXT",
            "attachment_path": "TEXT",
            "attachment_mime": "TEXT",
            "attachment_size": "TEXT",
        }
        for c, typ in needed.items():
            if c not in cols:
                cur.execute(f"ALTER TABLE messages ADD COLUMN {c} {typ}")
        con.commit()
    finally:
        con.close()



def _ensure_user_avatar_column():
    db_path = os.path.join(os.path.dirname(__file__), "chat.db")
    if not os.path.exists(db_path):
        return
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cur.fetchall()}
        if "avatar_path" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN avatar_path TEXT")
        con.commit()
    finally:
        con.close()

def _ensure_conversation_owner_column():
    db_path = os.path.join(os.path.dirname(__file__), "chat.db")
    if not os.path.exists(db_path):
        return
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("PRAGMA table_info(conversations)")
        cols = {row[1] for row in cur.fetchall()}
        if "owner_id" not in cols:
            cur.execute("ALTER TABLE conversations ADD COLUMN owner_id TEXT")
        con.commit()
    finally:
        con.close()


_ensure_message_attachment_columns()
_ensure_user_avatar_column()
_ensure_conversation_owner_column()


app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB upload limit
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
AVATAR_DIR = os.path.join(UPLOAD_DIR, "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)

app.config["SECRET_KEY"] = os.getenv("PYCORD_SECRET", "CHANGE_ME_TO_A_RANDOM_SECRET")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
signer = SessionSigner(secret=os.getenv("PYCORD_SECRET", "CHANGE_ME_TO_A_RANDOM_SECRET"))

ADJECTIVES = [
    "Dangerous","Silent","Electric","Cosmic","Velvet","Clever","Crimson","Icy","Golden","Rapid",
    "Mysterious","Wild","Neon","Hidden","Brave","Stormy","Midnight","Nimble","Radiant","Fierce"
]
NOUNS = [
    "Raptor","Falcon","Comet","Tiger","Lantern","Voyager","Dragon","Otter","Phoenix","Warden",
    "Nomad","Sparrow","Golem","Cipher","Rocket","Tornado","Wolf","Mirage","Harbor","Saturn"
]
def random_group_name() -> str:
    return f"{secrets.choice(ADJECTIVES)} {secrets.choice(NOUNS)}"

def db_session():
    return SessionLocal()

def get_session_data():
    token = request.cookies.get("session")
    if not token:
        return None
    return signer.verify(token)

def current_user_or_401(db):
    sd = get_session_data()
    if not sd:
        abort(401)
    u = db.query(User).filter(User.id == sd["uid"]).first()
    if not u:
        abort(401)
    return u, sd

def csrf_or_403(sd):
    csrf = request.form.get("csrf", "")
    if not secrets.compare_digest(sd["csrf"], csrf):
        abort(403)

def set_session_cookie(resp, user_id: str):
    csrf = new_csrf()
    token = signer.sign(user_id, csrf)
    resp.set_cookie(
        "session",
        token,
        httponly=True,
        samesite="Strict",
        # secure=True,  # enable if using HTTPS
        max_age=60 * 60 * 24 * 7,
    )

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@app.get("/favicon.ico")
def favicon():
    return ("", 204)

@app.get("/")
def home():
    if get_session_data():
        return redirect("/app")
    return redirect("/login")

@app.get("/login")
def login_get():
    return render_template("login.html", error=None)

@app.post("/login")
def login_post():
    db = db_session()
    try:
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            return render_template("login.html", error="Invalid username or password.")
        resp = make_response(redirect("/app"))
        set_session_cookie(resp, user.id)
        return resp
    finally:
        db.close()

@app.get("/register")
def register_get():
    return render_template("register.html", error=None)

@app.post("/register")
def register_post():
    db = db_session()
    try:
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if len(username) < 3 or len(username) > 24:
            return render_template("register.html", error="Username must be 3–24 characters.")
        if len(password) < 10:
            return render_template("register.html", error="Password must be at least 10 characters.")
        if db.query(User).filter(User.username == username).first():
            return render_template("register.html", error="Username already taken.")
        user = User(username=username, password_hash=hash_password(password))
        db.add(user); db.commit(); db.refresh(user)
        resp = make_response(redirect("/app"))
        set_session_cookie(resp, user.id)
        return resp
    finally:
        db.close()

@app.post("/logout")
def logout_post():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        resp = make_response(redirect("/login"))
        resp.delete_cookie("session")
        return resp
    finally:
        db.close()

def accepted_friends(db, user_id: str):
    q = db.query(Friendship).filter(
        and_(Friendship.status == "accepted",
             or_(Friendship.requester_id == user_id, Friendship.addressee_id == user_id))
    ).all()
    ids = [(f.addressee_id if f.requester_id == user_id else f.requester_id) for f in q]
    return db.query(User).filter(User.id.in_(ids)).order_by(User.username.asc()).all() if ids else []

def pending_incoming(db, user_id: str):
    reqs = db.query(Friendship).filter(Friendship.addressee_id == user_id, Friendship.status == "pending").all()
    out = []
    for r in reqs:
        u = db.query(User).filter(User.id == r.requester_id).first()
        if u:
            out.append({"id": r.id, "from_username": u.username})
    out.sort(key=lambda x: x["from_username"].lower())
    return out

def dm_key(a: str, b: str) -> str:
    return ":".join(sorted([a, b]))

def ensure_dm(db, a: str, b: str) -> Conversation:
    key = dm_key(a, b)
    convo = db.query(Conversation).filter(Conversation.type == "dm", Conversation.dm_key == key).first()
    if convo:
        return convo
    convo = Conversation(type="dm", dm_key=key)
    db.add(convo); db.commit(); db.refresh(convo)
    for uid in [a, b]:
        db.add(ConversationMember(conversation_id=convo.id, user_id=uid))
    db.commit()
    return convo

def is_member(db, conversation_id: str, user_id: str) -> bool:
    return db.query(ConversationMember).filter(
        ConversationMember.conversation_id == conversation_id,
        ConversationMember.user_id == user_id
    ).first() is not None

def user_conversations(db, user_id: str):
    rows = (db.query(Conversation)
            .join(ConversationMember, ConversationMember.conversation_id == Conversation.id)
            .filter(ConversationMember.user_id == user_id)
            .order_by(Conversation.created_at.desc())
            .all())
    convos = [{"id": c.id, "type": c.type, "name": (c.name or "Direct Message")} for c in rows]
    for c in convos:
        if c["type"] == "dm":
            members = db.query(ConversationMember).filter(ConversationMember.conversation_id == c["id"]).all()
            other_id = next((m.user_id for m in members if m.user_id != user_id), None)
            if other_id:
                other = db.query(User).filter(User.id == other_id).first()
                if other:
                    c["name"] = other.username
    return convos

@app.get("/app")
def app_page():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        friends = accepted_friends(db, user.id)
        pending = pending_incoming(db, user.id)
        convos = user_conversations(db, user.id)

        selected_id = convos[0]["id"] if convos else None
        selected_name = convos[0]["name"] if convos else None

        messages = []
        if selected_id:
            msgs_db = (db.query(Message)
                       .filter(Message.conversation_id == selected_id)
                       .order_by(Message.created_at.desc())
                       .limit(75).all())
            msgs_db = list(reversed(msgs_db))
            messages = [{"id": m.id, "content": m.content, "created_at": m.created_at.isoformat(), "username": m.user.username, "avatar_url": (f"/avatars/{m.user.id}" if m.user.avatar_path else None), "attachment_name": m.attachment_name, "has_attachment": bool(m.attachment_path)} for m in msgs_db]

        friends_list = [{"id": f.id, "username": f.username} for f in friends]
        sess_token = request.cookies.get("session", "")
        return render_template("app.html",
                               username=user.username,
                               session=sess_token,
                               csrf=sd["csrf"],
                               friends=friends_list,
                               pending=pending,
                               convos=convos,
                               selected_id=selected_id,
                               selected_name=selected_name,
                               messages=messages)
    finally:
        db.close()

@app.post("/friends/add")
def friends_add():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        target_name = (request.form.get("username") or "").strip()
        if not target_name or target_name.lower() == user.username.lower():
            return redirect("/app")
        target = db.query(User).filter(User.username == target_name).first()
        if not target:
            return redirect("/app")

        reverse = db.query(Friendship).filter(Friendship.requester_id == target.id, Friendship.addressee_id == user.id).first()
        if reverse and reverse.status == "pending":
            reverse.status = "accepted"; db.add(reverse)
            forward = db.query(Friendship).filter(Friendship.requester_id == user.id, Friendship.addressee_id == target.id).first()
            if not forward:
                forward = Friendship(requester_id=user.id, addressee_id=target.id, status="accepted")
            else:
                forward.status = "accepted"
            db.add(forward); db.commit()
            ensure_dm(db, user.id, target.id)
            return redirect("/app")

        existing = db.query(Friendship).filter(Friendship.requester_id == user.id, Friendship.addressee_id == target.id).first()
        if not existing:
            db.add(Friendship(requester_id=user.id, addressee_id=target.id, status="pending"))
            db.commit()
        return redirect("/app")
    finally:
        db.close()

@app.post("/friends/accept")
def friends_accept():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        req_id = request.form.get("req_id") or ""
        fr = db.query(Friendship).filter(Friendship.id == req_id, Friendship.addressee_id == user.id).first()
        if not fr or fr.status != "pending":
            return redirect("/app")
        fr.status = "accepted"; db.add(fr)
        back = db.query(Friendship).filter(Friendship.requester_id == user.id, Friendship.addressee_id == fr.requester_id).first()
        if not back:
            back = Friendship(requester_id=user.id, addressee_id=fr.requester_id, status="accepted")
        else:
            back.status = "accepted"
        db.add(back); db.commit()
        ensure_dm(db, user.id, fr.requester_id)
        return redirect("/app")
    finally:
        db.close()


@app.post("/friends/ignore")
def friends_ignore():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        req_id = request.form.get("req_id") or ""
        fr = db.query(Friendship).filter(Friendship.id == req_id, Friendship.addressee_id == user.id).first()
        if fr and fr.status == "pending":
            db.delete(fr); db.commit()
        return redirect("/app")
    finally:
        db.close()

@app.post("/friends/remove")
def friends_remove():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        fid = request.form.get("friend_id") or ""
        if not fid:
            return redirect("/app")
        a = db.query(Friendship).filter(Friendship.requester_id == user.id, Friendship.addressee_id == fid, Friendship.status == "accepted").first()
        b = db.query(Friendship).filter(Friendship.requester_id == fid, Friendship.addressee_id == user.id, Friendship.status == "accepted").first()
        if a: db.delete(a)
        if b: db.delete(b)
        db.commit()
        return redirect("/app")
    finally:
        db.close()

@app.post("/groups/create")
def groups_create():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        raw = [x.strip() for x in (request.form.get("member_ids") or "").split(",") if x.strip()]
        allowed = {f.id for f in accepted_friends(db, user.id)}
        selected = [mid for mid in raw if mid in allowed]
        if not selected:
            return redirect("/app")
        convo = Conversation(type="group", name=random_group_name(), owner_id=user.id)
        db.add(convo); db.commit(); db.refresh(convo)
        for uid in set(selected + [user.id]):
            db.add(ConversationMember(conversation_id=convo.id, user_id=uid))
        db.commit()
        return redirect("/app")
    finally:
        db.close()


@app.post("/announcements/create")
def announcements_create():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        raw = [x.strip() for x in (request.form.get("member_ids") or "").split(",") if x.strip()]
        allowed = {f.id for f in accepted_friends(db, user.id)}
        selected = [mid for mid in raw if mid in allowed]
        if not selected:
            return redirect("/app")
        convo = Conversation(type="announcement", name=f"{random_group_name()} Announcements", owner_id=user.id)
        db.add(convo); db.commit(); db.refresh(convo)
        for uid in set(selected + [user.id]):
            role = "owner" if uid == user.id else "member"
            db.add(ConversationMember(conversation_id=convo.id, user_id=uid, role=role))
        db.commit()
        return redirect("/app")
    finally:
        db.close()

@app.get("/api/conversations/<conversation_id>/messages")
def api_messages(conversation_id: str):
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        if not is_member(db, conversation_id, user.id):
            abort(403)
        msgs_db = (db.query(Message)
                   .filter(Message.conversation_id == conversation_id)
                   .order_by(Message.created_at.desc())
                   .limit(200).all())
        msgs_db = list(reversed(msgs_db))
        return jsonify([{"id": m.id, "content": m.content, "created_at": m.created_at.isoformat(), "username": m.user.username, "avatar_url": (f"/avatars/{m.user.id}" if m.user.avatar_path else None), "attachment_name": m.attachment_name, "has_attachment": bool(m.attachment_path)} for m in msgs_db])
    finally:
        db.close()



@app.get("/profile")
def profile_page():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        return render_template("profile.html", username=user.username, csrf=sd["csrf"], session=sd["session"], avatar_url=(f"/avatars/{user.id}" if user.avatar_path else None))
    finally:
        db.close()

@app.post("/profile/avatar")
def profile_avatar_upload():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)
        f = request.files.get("avatar")
        if not f or not f.filename:
            return redirect("/profile")
        # accept common image types
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in [".png",".jpg",".jpeg",".webp"]:
            return redirect("/profile")
        path = os.path.join(AVATAR_DIR, f"{user.id}{ext}")
        f.save(path)
        user.avatar_path = path
        db.add(user); db.commit()
        return redirect("/profile")
    finally:
        db.close()

@app.get("/avatars/<user_id>")
def avatar_get(user_id: str):
    db = db_session()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u or not u.avatar_path:
            abort(404)
        if not os.path.isfile(u.avatar_path):
            abort(404)
        mime = mimetypes.guess_type(u.avatar_path)[0] or "application/octet-stream"
        return send_file(u.avatar_path, mimetype=mime, max_age=3600)
    finally:
        db.close()

@app.get("/files/<message_id>")
def download_file(message_id: str):
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        msg = db.query(Message).filter(Message.id == message_id).first()
        if not msg or not msg.attachment_path:
            abort(404)
        if not is_member(db, msg.conversation_id, user.id):
            abort(403)
        path = msg.attachment_path
        if not os.path.isfile(path):
            abort(404)
        return send_file(path, as_attachment=True, download_name=msg.attachment_name or "file")
    finally:
        db.close()

@app.errorhandler(413)
def too_large(e):
    return ("File too large (max 10MB).", 413)

@app.post("/upload")
def upload_file():
    db = db_session()
    try:
        user, sd = current_user_or_401(db)
        csrf_or_403(sd)

        convo_id = (request.form.get("conversation_id") or "").strip()
        if not convo_id or not is_member(db, convo_id, user.id):
            abort(403)

        f = request.files.get("file")
        if not f or not f.filename:
            abort(400)

        filename = secure_filename(f.filename)
        if not filename:
            abort(400)

        # Save to uploads folder with unique prefix
        msg = Message(conversation_id=convo_id, user_id=user.id, content="")
        msg.attachment_name = filename
        msg.attachment_mime = f.mimetype or "application/octet-stream"
        db.add(msg)
        db.commit()
        db.refresh(msg)

        save_path = os.path.join(UPLOAD_DIR, f"{msg.id}_{filename}")
        f.save(save_path)

        try:
            size = os.path.getsize(save_path)
        except Exception:
            size = 0

        msg.attachment_path = save_path
        msg.attachment_size = str(size)
        msg.content = f"📎 {filename}"
        db.add(msg)
        db.commit()
        db.refresh(msg)

        payload = {
            "id": msg.id,
            "conversationId": convo_id,
            "content": msg.content,
            "createdAt": msg.created_at.isoformat(),
            "user": {"username": user.username},
            "attachment_name": msg.attachment_name,
            "file_url": f"/files/{msg.id}",
            "has_attachment": True,
        }
    finally:
        db.close()

    # Broadcast like a normal message
    socketio.emit("message_new", payload, room=f"convo:{convo_id}")
    return jsonify({"ok": True, "message": payload})

@socketio.on("connect")
def sio_connect(auth):
    token = (auth or {}).get("session")
    data = signer.verify(token) if token else None
    if not data:
        return False
    from flask import session as fl_sess
    fl_sess["uid"] = data["uid"]
    emit("connected", {"ok": True})

@socketio.on("convo_join")
def sio_join(data):
    convo_id = (data or {}).get("conversationId")
    if not convo_id:
        return
    from flask import session as fl_sess
    uid = fl_sess.get("uid")
    if not uid:
        return
    db = db_session()
    try:
        if not is_member(db, convo_id, uid):
            return
        convo = db.query(Conversation).filter(Conversation.id == convo_id).first()
        if not convo:
            return
        if convo.type == "announcement" and convo.owner_id != uid:
            return
    finally:
        db.close()
    join_room(f"convo:{convo_id}")

@socketio.on("message_send")
def sio_send(data):
    convo_id = (data or {}).get("conversationId")
    content = (data or {}).get("content", "").strip()
    if not convo_id or not content:
        return
    if len(content) > 4000:
        content = content[:4000]
    from flask import session as fl_sess
    uid = fl_sess.get("uid")
    if not uid:
        return
    db = db_session()
    try:
        if not is_member(db, convo_id, uid):
            return
        convo = db.query(Conversation).filter(Conversation.id == convo_id).first()
        if not convo:
            return
        if convo.type == "announcement" and convo.owner_id != uid:
            return
        user = db.query(User).filter(User.id == uid).first()
        if not user:
            return
        msg = Message(conversation_id=convo_id, user_id=user.id, content=content)
        db.add(msg); db.commit(); db.refresh(msg)
        payload = {"id": msg.id, "conversationId": convo_id, "content": msg.content,
                   "createdAt": msg.created_at.isoformat(), "user": {"username": user.username, "avatar_url": (f"/avatars/{user.id}" if user.avatar_path else None)}}
    finally:
        db.close()
    socketio.emit("message_new", payload, room=f"convo:{convo_id}")

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=4000, debug=True)


@socketio.on("call_offer")
def sio_call_offer(data):
    convo_id = (data or {}).get("conversationId")
    sdp = (data or {}).get("sdp")
    if not convo_id or not sdp:
        return
    from flask import session as fl_sess
    uid = fl_sess.get("uid")
    if not uid:
        return
    db = db_session()
    try:
        if not is_member(db, convo_id, uid):
            return
        user = db.query(User).filter(User.id == uid).first()
        convo = db.query(Conversation).filter(Conversation.id == convo_id).first()
        if not user or not convo:
            return
        # Only allow calls in DMs for simplicity
        if convo.type != "dm":
            return
        payload = {"conversationId": convo_id, "from": {"id": uid, "username": user.username}, "sdp": sdp}
    finally:
        db.close()
    emit("call_offer", payload, room=f"convo:{convo_id}", include_self=False)

@socketio.on("call_answer")
def sio_call_answer(data):
    convo_id = (data or {}).get("conversationId")
    sdp = (data or {}).get("sdp")
    if not convo_id or not sdp:
        return
    from flask import session as fl_sess
    uid = fl_sess.get("uid")
    if not uid:
        return
    db = db_session()
    try:
        if not is_member(db, convo_id, uid):
            return
        user = db.query(User).filter(User.id == uid).first()
        convo = db.query(Conversation).filter(Conversation.id == convo_id).first()
        if not user or not convo or convo.type != "dm":
            return
        payload = {"conversationId": convo_id, "from": {"id": uid, "username": user.username}, "sdp": sdp}
    finally:
        db.close()
    emit("call_answer", payload, room=f"convo:{convo_id}", include_self=False)

@socketio.on("call_ice")
def sio_call_ice(data):
    convo_id = (data or {}).get("conversationId")
    cand = (data or {}).get("candidate")
    if not convo_id or not cand:
        return
    from flask import session as fl_sess
    uid = fl_sess.get("uid")
    if not uid:
        return
    db = db_session()
    try:
        if not is_member(db, convo_id, uid):
            return
        convo = db.query(Conversation).filter(Conversation.id == convo_id).first()
        if not convo or convo.type != "dm":
            return
    finally:
        db.close()
    emit("call_ice", {"conversationId": convo_id, "candidate": cand}, room=f"convo:{convo_id}", include_self=False)

@socketio.on("call_hangup")
def sio_call_hangup(data):
    convo_id = (data or {}).get("conversationId")
    if not convo_id:
        return
    emit("call_hangup", {"conversationId": convo_id}, room=f"convo:{convo_id}", include_self=False)
