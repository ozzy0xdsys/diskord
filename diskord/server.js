const fs = require("fs");
const path = require("path");
const http = require("http");
const express = require("express");
const bcrypt = require("bcryptjs");
const { nanoid } = require("nanoid");
const WebSocket = require("ws");

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

function readUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function safeUser(u) {
  return { id: u.id, username: u.username, createdAt: u.createdAt };
}

function makeCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const pick = () => alphabet[Math.floor(Math.random() * alphabet.length)];
  const block = () => Array.from({ length: 4 }, pick).join("");
  return `${block()}-${block()}`;
}

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use("/static", express.static(path.join(__dirname, "public"), { maxAge: 0 }));

// In-memory auth tokens (reset on restart)
const tokens = new Map(); // token -> userId

app.get("/", (req, res) => res.redirect("/login"));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/app", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));
app.get("/privacy", (req, res) => res.sendFile(path.join(__dirname, "public", "privacy.html")));

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  const u = (username || "").trim();
  const p = (password || "").toString();
  if (!u || u.length < 3 || u.length > 20) return res.status(400).json({ error: "Username must be 3–20 chars." });
  if (!p || p.length < 8) return res.status(400).json({ error: "Password must be at least 8 chars." });

  const users = readUsers();
  const taken = users.some(x => x.username.toLowerCase() === u.toLowerCase());
  if (taken) return res.status(409).json({ error: "Username already exists." });

  const hash = await bcrypt.hash(p, 12);
  const user = { id: nanoid(12), username: u, passHash: hash, createdAt: new Date().toISOString() };
  users.push(user);
  writeUsers(users);

  const token = nanoid(32);
  tokens.set(token, user.id);
  return res.json({ token, user: safeUser(user) });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  const u = (username || "").trim();
  const p = (password || "").toString();

  const users = readUsers();
  const user = users.find(x => x.username.toLowerCase() === u.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials." });

  const ok = await bcrypt.compare(p, user.passHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials." });

  const token = nanoid(32);
  tokens.set(token, user.id);
  return res.json({ token, user: safeUser(user) });
});

app.post("/api/logout", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "") || "";
  if (token) tokens.delete(token);
  res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const sessions = new Map(); // code -> { creatorId, members:Set(userId), sockets:Set(ws) }

function getUserById(id) {
  const users = readUsers();
  return users.find(u => u.id === id);
}

function wsSend(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function broadcast(code, obj) {
  const s = sessions.get(code);
  if (!s) return;
  for (const sock of s.sockets) wsSend(sock, obj);
}
function removeSocketFromSession(ws) {
  if (!ws.sessionCode || !sessions.has(ws.sessionCode)) return;
  const code = ws.sessionCode;
  const s = sessions.get(code);
  s.sockets.delete(ws);
  if (ws.userId) s.members.delete(ws.userId);

  broadcast(code, { type: "presence", event: "leave", userId: ws.userId, username: ws.username });

  if (s.sockets.size === 0) sessions.delete(code);
  ws.sessionCode = null;
}

wss.on("connection", (ws, req) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get("token") || "";
    const userId = tokens.get(token);
    if (!userId) return ws.close(1008, "unauthorized");

    const user = getUserById(userId);
    if (!user) return ws.close(1008, "unauthorized");

    ws.userId = user.id;
    ws.username = user.username;
    ws.sessionCode = null;

    wsSend(ws, { type: "hello", user: safeUser(user) });

    ws.on("message", (buf) => {
      let msg;
      try { msg = JSON.parse(buf.toString("utf8")); } catch { return; }

      if (msg.type === "create_session") {
        removeSocketFromSession(ws);
        let code;
        do { code = makeCode(); } while (sessions.has(code));
        sessions.set(code, { creatorId: ws.userId, members: new Set([ws.userId]), sockets: new Set([ws]) });
        ws.sessionCode = code;

        wsSend(ws, { type: "session", event: "created", code, creator: true });
        broadcast(code, { type: "presence", event: "join", userId: ws.userId, username: ws.username });
        return;
      }

      if (msg.type === "join_session") {
        const code = (msg.code || "").toString().trim().toUpperCase();
        if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) {
          wsSend(ws, { type: "error", message: "Invalid code format." });
          return;
        }
        const s = sessions.get(code);
        if (!s) {
          wsSend(ws, { type: "error", message: "Session not found." });
          return;
        }
        removeSocketFromSession(ws);
        s.sockets.add(ws);
        s.members.add(ws.userId);
        ws.sessionCode = code;

        wsSend(ws, { type: "session", event: "joined", code, creator: s.creatorId === ws.userId });
        broadcast(code, { type: "presence", event: "join", userId: ws.userId, username: ws.username });
        return;
      }

      if (msg.type === "end_session") {
        const code = ws.sessionCode;
        const s = code ? sessions.get(code) : null;
        if (!s) return;
        if (s.creatorId !== ws.userId) {
          wsSend(ws, { type: "error", message: "Only the session creator can end the session." });
          return;
        }
        broadcast(code, { type: "session", event: "ended", code });
        for (const sock of s.sockets) sock.sessionCode = null;
        sessions.delete(code);
        return;
      }

      if (msg.type === "cipher") {
        const code = ws.sessionCode;
        if (!code || !sessions.has(code)) {
          wsSend(ws, { type: "error", message: "Join a session first." });
          return;
        }
        const payload = {
          type: "cipher",
          kind: msg.kind,
          from: { userId: ws.userId, username: ws.username },
          ts: Date.now(),
          iv: msg.iv,
          data: msg.data,
          name: msg.name,
          mime: msg.mime,
          size: msg.size
        };
        broadcast(code, payload);
      }
    });

    ws.on("close", () => removeSocketFromSession(ws));
    ws.on("error", () => removeSocketFromSession(ws));
  } catch {
    try { ws.close(1011, "server error"); } catch {}
  }
});

server.listen(PORT, () => console.log(`Diskord listening on http://127.0.0.1:${PORT}`));
