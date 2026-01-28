import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import { WebSocketServer } from "ws";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";
import { customAlphabet } from "nanoid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "diskord.sqlite");

const nanoAlpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/1/0
const nano = customAlphabet(nanoAlpha, 8);

function makeCode() {
  const a = nano();
  return a.slice(0, 4) + "-" + a.slice(4, 8);
}

function nowIso() {
  return new Date().toISOString();
}

function ensureDir(p) {
  try { import("fs").then(fs => fs.default.mkdirSync(p, { recursive: true })); } catch {}
}

ensureDir(DATA_DIR);

const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`PRAGMA journal_mode=WAL;`);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      code TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_code TEXT NOT NULL,
      sender TEXT NOT NULL,
      kind TEXT NOT NULL, -- "text" | "file"
      payload TEXT NOT NULL, -- encrypted blob (base64/json string)
      meta TEXT NOT NULL, -- json for filename/mime/size; server can't read message content
      created_at TEXT NOT NULL
    )
  `);
});

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(express.static(path.join(__dirname, "public"), {
  setHeaders(res) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
  }
}));

// --- tiny auth token (HMAC-less, just random) ---
import crypto from "crypto";
const TOK_TTL_MS = 1000 * 60 * 60 * 12; // 12h
const tokens = new Map(); // token -> { username, exp }

function issueToken(username) {
  const token = crypto.randomBytes(24).toString("base64url");
  tokens.set(token, { username, exp: Date.now() + TOK_TTL_MS });
  return token;
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const t = tokens.get(token);
  if (!t) return res.status(401).json({ error: "unauthorized" });
  if (t.exp < Date.now()) { tokens.delete(token); return res.status(401).json({ error: "expired" }); }
  req.user = t.username;
  next();
}

// login-or-register: if user doesn't exist, create.
app.post("/api/auth", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: "bad_username" });
  if (String(password).length < 6) return res.status(400).json({ error: "weak_password" });

  db.get("SELECT username, password_hash FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) return res.status(500).json({ error: "db_error" });
    if (!row) {
      const password_hash = await bcrypt.hash(password, 12);
      db.run("INSERT INTO users(username, password_hash, created_at) VALUES (?,?,?)", [username, password_hash, nowIso()], (err2) => {
        if (err2) return res.status(500).json({ error: "db_error" });
        const token = issueToken(username);
        return res.json({ token, username, created: true });
      });
    } else {
      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok) return res.status(403).json({ error: "bad_password" });
      const token = issueToken(username);
      return res.json({ token, username, created: false });
    }
  });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ username: req.user });
});

// create session
app.post("/api/sessions", auth, (req, res) => {
  const code = makeCode();
  const owner = req.user;
  db.run("INSERT INTO sessions(code, owner, created_at) VALUES (?,?,?)", [code, owner, nowIso()], (err) => {
    if (err) return res.status(500).json({ error: "db_error" });
    res.json({ code, owner });
  });
});

// list active sessions (created by anyone) — for demo. In production, you might only list sessions you joined.
app.get("/api/sessions", auth, (req, res) => {
  db.all("SELECT code, owner, created_at FROM sessions ORDER BY created_at DESC LIMIT 50", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "db_error" });
    res.json({ sessions: rows });
  });
});

// end session (only owner)
app.delete("/api/sessions/:code", auth, (req, res) => {
  const code = (req.params.code || "").toUpperCase();
  db.get("SELECT owner FROM sessions WHERE code = ?", [code], (err, row) => {
    if (err) return res.status(500).json({ error: "db_error" });
    if (!row) return res.status(404).json({ error: "not_found" });
    if (row.owner !== req.user) return res.status(403).json({ error: "not_owner" });

    db.serialize(() => {
      db.run("DELETE FROM messages WHERE session_code = ?", [code]);
      db.run("DELETE FROM sessions WHERE code = ?", [code], (err2) => {
        if (err2) return res.status(500).json({ error: "db_error" });
        broadcastToSession(code, { type: "session_ended", code });
        closeAllInSession(code);
        res.json({ ok: true });
      });
    });
  });
});

// load message history (encrypted)
app.get("/api/sessions/:code/messages", auth, (req, res) => {
  const code = (req.params.code || "").toUpperCase();
  db.get("SELECT code FROM sessions WHERE code = ?", [code], (err, row) => {
    if (err) return res.status(500).json({ error: "db_error" });
    if (!row) return res.status(404).json({ error: "not_found" });

    db.all(
      "SELECT id, sender, kind, payload, meta, created_at FROM messages WHERE session_code = ? ORDER BY id ASC LIMIT 500",
      [code],
      (err2, rows) => {
        if (err2) return res.status(500).json({ error: "db_error" });
        res.json({ messages: rows.map(r => ({ ...r, meta: safeJson(r.meta) })) });
      }
    );
  });
});

function safeJson(s) { try { return JSON.parse(s); } catch { return {}; } }

// WebSocket
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * clients: ws -> { username, sessionCode }
 */
const clients = new Map();
const sessionMembers = new Map(); // code -> Set<ws>

function broadcastToSession(code, msgObj) {
  const set = sessionMembers.get(code);
  if (!set) return;
  const data = JSON.stringify(msgObj);
  for (const ws of set) {
    if (ws.readyState === 1) ws.send(data);
  }
}

function closeAllInSession(code) {
  const set = sessionMembers.get(code);
  if (!set) return;
  for (const ws of set) {
    try { ws.close(4001, "Session ended"); } catch {}
  }
  sessionMembers.delete(code);
}

function memberCount(code) {
  const set = sessionMembers.get(code);
  return set ? set.size : 0;
}

wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString("utf8")); } catch { return; }

    // first message must be hello: {type:"hello", token, code}
    if (msg.type === "hello") {
      const token = String(msg.token || "");
      const code = String(msg.code || "").toUpperCase();
      const t = tokens.get(token);
      if (!t || t.exp < Date.now()) { try { ws.close(4003, "Unauthorized"); } catch {} ; return; }

      db.get("SELECT code, owner FROM sessions WHERE code = ?", [code], (err, row) => {
        if (err || !row) { try { ws.close(4004, "No such session"); } catch {} ; return; }
        clients.set(ws, { username: t.username, sessionCode: code });
        if (!sessionMembers.has(code)) sessionMembers.set(code, new Set());
        sessionMembers.get(code).add(ws);

        broadcastToSession(code, { type: "member_join", username: t.username, members: memberCount(code) });
        ws.send(JSON.stringify({ type: "hello_ok", code, owner: row.owner, members: memberCount(code) }));
      });
      return;
    }

    const info = clients.get(ws);
    if (!info) return;

    if (msg.type === "send") {
      // payload is encrypted string; meta is JSON (filename/mime/size) but not content
      const payload = String(msg.payload || "");
      const kind = msg.kind === "file" ? "file" : "text";
      const meta = JSON.stringify(msg.meta || {});
      if (!payload || payload.length > 5_000_000) return;

      db.run(
        "INSERT INTO messages(session_code, sender, kind, payload, meta, created_at) VALUES (?,?,?,?,?,?)",
        [info.sessionCode, info.username, kind, payload, meta, nowIso()],
        function (err) {
          if (err) return;
          broadcastToSession(info.sessionCode, {
            type: "message",
            message: {
              id: this.lastID,
              session_code: info.sessionCode,
              sender: info.username,
              kind,
              payload,
              meta: JSON.parse(meta),
              created_at: nowIso()
            }
          });
        }
      );
      return;
    }

    if (msg.type === "leave") {
      try { ws.close(1000, "bye"); } catch {}
    }
  });

  ws.on("close", () => {
    const info = clients.get(ws);
    if (!info) return;
    clients.delete(ws);
    const set = sessionMembers.get(info.sessionCode);
    if (set) {
      set.delete(ws);
      if (set.size === 0) sessionMembers.delete(info.sessionCode);
    }
    broadcastToSession(info.sessionCode, { type: "member_leave", username: info.username, members: memberCount(info.sessionCode) });
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Diskord listening on http://0.0.0.0:${PORT}`);
});
