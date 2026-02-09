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
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function safeUser(u) {
  return { id: u.id, username: u.username, createdAt: u.createdAt };
}
function getUserById(id) {
  const users = readUsers();
  return users.find((u) => u.id === id);
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

function authUser(req) {
  const token = req.headers.authorization?.replace("Bearer ", "") || "";
  const userId = tokens.get(token);
  if (!userId) return null;
  return getUserById(userId);
}

app.get("/api/me", (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: "unauthorized" });
  return res.json({ user: safeUser(user) });
});

app.post("/api/change_password", async (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: "unauthorized" });
  const { currentPassword, newPassword } = req.body || {};
  const cur = (currentPassword || "").toString();
  const next = (newPassword || "").toString();
  if (!next || next.length < 8) return res.status(400).json({ error: "Password must be at least 8 chars." });

  const ok = await bcrypt.compare(cur, user.passHash);
  if (!ok) return res.status(401).json({ error: "Invalid current password." });

  const users = readUsers();
  const idx = users.findIndex((u) => u.id === user.id);
  if (idx < 0) return res.status(404).json({ error: "Not found." });
  users[idx].passHash = await bcrypt.hash(next, 12);
  writeUsers(users);
  return res.json({ ok: true });
});

app.get("/", (req, res) => res.redirect("/login"));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/app", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));
app.get("/privacy", (req, res) => res.sendFile(path.join(__dirname, "public", "privacy.html")));

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  const u = (username || "").trim();
  const p = (password || "").toString();
  if (!u || u.length < 3 || u.length > 20) return res.status(400).json({ error: "Username must be 3–20 chars." });
  if (!p || p.length < 8) return res.status(400).json({ error: "Password must be at least 8 chars." });

  const users = readUsers();
  const taken = users.some((x) => x.username.toLowerCase() === u.toLowerCase());
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
  const user = users.find((x) => x.username.toLowerCase() === u.toLowerCase());
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

/**
 * sessions: code -> {
 *   creatorId,
 *   sockets:Set(ws),
 *   memberCounts:Map(userId->count),
 *   memberNames:Map(userId->username),
 *   leaveTimers:Map(userId->timeout)
 * }
 */
const sessions = new Map();

function wsSend(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function broadcast(code, obj) {
  const s = sessions.get(code);
  if (!s) return;
  for (const sock of s.sockets) wsSend(sock, obj);
}
function ensureSession(code, creatorId) {
  if (!sessions.has(code)) {
    sessions.set(code, {
      creatorId,
      sockets: new Set(),
      memberCounts: new Map(),
      memberNames: new Map(),
      leaveTimers: new Map(),
    });
  }
  return sessions.get(code);
}
function listMembers(code) {
  const s = sessions.get(code);
  if (!s) return [];
  const out = [];
  for (const [userId, username] of s.memberNames.entries()) out.push({ userId, username });
  out.sort((a, b) => (a.username || "").localeCompare(b.username || ""));
  return out;
}
function clearLeaveTimer(s, userId) {
  const t = s.leaveTimers.get(userId);
  if (t) {
    clearTimeout(t);
    s.leaveTimers.delete(userId);
  }
}

function joinSession(ws, code) {
  const s = sessions.get(code);
  if (!s) return false;

  // If the user is in the "refresh grace period", treat this as a reconnect.
  const hadGrace = s.leaveTimers.has(ws.userId);

  s.sockets.add(ws);
  ws.sessionCodes.add(code);

  clearLeaveTimer(s, ws.userId);

  const prev = s.memberCounts.get(ws.userId) || 0;
  s.memberCounts.set(ws.userId, prev + 1);
  s.memberNames.set(ws.userId, ws.username);

  // Broadcast join only if truly new AND not reconnecting from grace.
  if (prev === 0 && !hadGrace) {
    broadcast(code, { type: "presence", code, event: "join", userId: ws.userId, username: ws.username });
    broadcast(code, { type: "members", code, members: listMembers(code) });
  } else if (prev === 0 && hadGrace) {
    // Reconnect: just refresh members list to this client.
    wsSend(ws, { type: "members", code, members: listMembers(code) });
  }
  return true;
}

function leaveSession(ws, code, reason = "leave") {
  const s = sessions.get(code);
  if (!s) return;

  ws.sessionCodes.delete(code);
  s.sockets.delete(ws);

  const prev = s.memberCounts.get(ws.userId) || 0;
  const next = Math.max(0, prev - 1);
  if (next === 0) s.memberCounts.delete(ws.userId);
  else s.memberCounts.set(ws.userId, next);

  if (next === 0) {
    if (reason === "disconnect") {
      // Grace period: don't broadcast leave immediately. This prevents refresh causing leave+join.
      clearLeaveTimer(s, ws.userId);
      const timer = setTimeout(() => {
        if (!(s.memberCounts.get(ws.userId) > 0)) {
          s.memberNames.delete(ws.userId);
          broadcast(code, { type: "presence", code, event: "leave", userId: ws.userId, username: ws.username });
          broadcast(code, { type: "members", code, members: listMembers(code) });
        }
        s.leaveTimers.delete(ws.userId);
        if (s.sockets.size === 0 && s.leaveTimers.size === 0) sessions.delete(code);
      }, 30000); // 30s grace
      s.leaveTimers.set(ws.userId, timer);
    } else {
      s.memberNames.delete(ws.userId);
      broadcast(code, { type: "presence", code, event: "leave", userId: ws.userId, username: ws.username });
      broadcast(code, { type: "members", code, members: listMembers(code) });
    }
  }

  if (s.sockets.size === 0 && s.leaveTimers.size === 0) sessions.delete(code);
}

function removeSocketFromAll(ws, reason = "disconnect") {
  for (const code of Array.from(ws.sessionCodes)) leaveSession(ws, code, reason);
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
    ws.sessionCodes = new Set();

    wsSend(ws, { type: "hello", user: safeUser(user) });

    ws.on("message", (buf) => {
      let msg;
      try {
        msg = JSON.parse(buf.toString("utf8"));
      } catch {
        return;
      }

      if (msg.type === "create_session") {
        let code;
        do {
          code = makeCode();
        } while (sessions.has(code));

        ensureSession(code, ws.userId);
        joinSession(ws, code);

        wsSend(ws, { type: "session", event: "created", code, creator: true });
        wsSend(ws, { type: "members", code, members: listMembers(code) });
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
        joinSession(ws, code);
        wsSend(ws, { type: "session", event: "joined", code, creator: s.creatorId === ws.userId });
        wsSend(ws, { type: "members", code, members: listMembers(code) });
        return;
      }

      if (msg.type === "leave_session") {
        const code = (msg.code || "").toString().trim().toUpperCase();
        if (!ws.sessionCodes.has(code)) return;
        leaveSession(ws, code, "leave");
        wsSend(ws, { type: "session", event: "left", code });
        return;
      }

      if (msg.type === "end_session") {
        const code = (msg.code || "").toString().trim().toUpperCase();
        const s = code ? sessions.get(code) : null;
        if (!s) return;
        if (s.creatorId !== ws.userId) {
          wsSend(ws, { type: "error", message: "Only the session creator can end the session." });
          return;
        }
        broadcast(code, { type: "session", event: "ended", code });

        for (const sock of s.sockets) sock.sessionCodes?.delete(code);
        sessions.delete(code);
        return;
      }

      if (msg.type === "cipher") {
        const code = (msg.code || "").toString().trim().toUpperCase();
        if (!code || !sessions.has(code)) {
          wsSend(ws, { type: "error", message: "Join a session first." });
          return;
        }
        if (!ws.sessionCodes.has(code)) {
          wsSend(ws, { type: "error", message: "You are not in that session." });
          return;
        }

        broadcast(code, {
          type: "cipher",
          kind: msg.kind,
          code,
          from: { userId: ws.userId, username: ws.username },
          ts: Date.now(),
          iv: msg.iv,
          data: msg.data,
          name: msg.name,
          mime: msg.mime,
          size: msg.size,
        });
        return;
      }
    });

    ws.on("close", () => removeSocketFromAll(ws, "disconnect"));
    ws.on("error", () => removeSocketFromAll(ws, "disconnect"));
  } catch {
    try {
      ws.close(1011, "server error");
    } catch {}
  }
});

server.listen(PORT, () => console.log(`Diskord listening on http://127.0.0.1:${PORT}`));
