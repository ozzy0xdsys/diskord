// Diskord client (multi-session, websocket, client-side encryption)
const token = localStorage.getItem("diskord_token");
if (!token) location.href = "/login";

const el = (id) => document.getElementById(id);

// Layout
const sessionListEl = el("sessionList");
const sessionTitleEl = el("sessionTitle");
const sessionMetaEl = el("sessionMeta");
const logEl = el("log");
const memberListEl = el("memberList");
const memberCountEl = el("memberCount");

// Controls
const createBtn = el("createBtn");
const joinBtn = el("joinBtn");
const leaveBtn = el("leaveBtn");
const endBtn = el("endBtn");
const logoutBtn = el("logoutBtn");
const settingsBtn = el("settingsBtn");

const msgBox = el("msg");
const sendBtn = el("sendBtn");
const attachBtn = el("attachBtn");
const fileInput = el("file");

// Join modal
const joinModal = el("modal");
const codeInput = el("codeInput");
const modalErr = el("modalErr");
const cancelBtn = el("cancelBtn");
const confirmJoinBtn = el("confirmJoinBtn");

// Settings modal
const settingsModal = el("settingsModal");
const closeSettingsBtn = el("closeSettingsBtn");
const curPass = el("curPass");
const newPass = el("newPass");
const savePassBtn = el("savePassBtn");
const passErr = el("passErr");
const passOk = el("passOk");

// Bottom-left user line
const meLine = el("meLine");

let ws = null;
let me = null;

// code -> { creator:boolean }
const sessions = new Map();
// code -> Map(userId->username)
const membersByCode = new Map();
// code -> CryptoKey (derived from code)
const sessionKeys = new Map();
// code -> message entries
const histories = new Map(); // entries: {kind:'system'|'msg', ts, text, from?{userId,username}, extraNode?}

let activeCode = null;
let pendingAutoJoin = new Set();
let requestedJoin = null;   // code string when user explicitly joins
let requestedCreate = false;

// ---------- persistence ----------
function loadJoinedCodes() {
  try {
    const raw = localStorage.getItem("diskord_joined") || "[]";
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}
function saveJoinedCodes(codes) {
  localStorage.setItem("diskord_joined", JSON.stringify(Array.from(new Set(codes))));
}
function saveActive(code) {
  if (code) localStorage.setItem("diskord_active", code);
  else localStorage.removeItem("diskord_active");
}
function loadActive() {
  return localStorage.getItem("diskord_active");
}

// ---------- utils ----------
function escapeHtml(s) {
  return (s || "")
    .toString()
    .replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
}
function timeStr(ts) {
  const d = new Date(ts || Date.now());
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function fmtUser(u) {
  return u?.username || "unknown";
}
function ensureHistory(code) {
  if (!histories.has(code)) histories.set(code, []);
  return histories.get(code);
}
function ensureMembers(code) {
  if (!membersByCode.has(code)) membersByCode.set(code, new Map());
  return membersByCode.get(code);
}
function ensureSessionKey(code) {
  if (!sessionKeys.has(code)) sessionKeys.set(code, deriveSessionKey(code));
  return sessionKeys.get(code);
}

// ---------- crypto (AES-GCM) ----------
async function deriveSessionKey(code) {
  // Deterministic key derived from the session code (shared secret).
  const enc = new TextEncoder().encode("diskord:" + code);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
function b64FromBytes(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function bytesFromB64(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
async function encryptBytes(key, ptBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ptBytes);
  return { iv: b64FromBytes(iv), data: b64FromBytes(new Uint8Array(ct)) };
}
async function decryptBytes(key, ivB64, dataB64) {
  const iv = bytesFromB64(ivB64);
  const data = bytesFromB64(dataB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new Uint8Array(pt);
}

// ---------- rendering ----------
function setActive(code) {
  activeCode = code || null;
  saveActive(activeCode);

  // Enable/disable controls
  const hasActive = !!activeCode;
  msgBox.disabled = !hasActive;
  sendBtn.disabled = !hasActive;
  attachBtn.disabled = !hasActive;
  leaveBtn.disabled = !hasActive;
  endBtn.disabled = !hasActive || !sessions.get(activeCode)?.creator;

  // Header
  if (!activeCode) {
    sessionTitleEl.textContent = "No session selected";
    sessionMetaEl.textContent = "Create or join a session to start.";
    logEl.innerHTML = "";
    memberListEl.innerHTML = "";
    memberCountEl.textContent = "0";
  } else {
    sessionTitleEl.textContent = activeCode;
    sessionMetaEl.textContent = sessions.get(activeCode)?.creator ? "You created this session." : "You're in this session.";
    renderHistory(activeCode);
    renderMembers(activeCode);
  }

  renderSessionList();
}

function renderSessionList() {
  sessionListEl.innerHTML = "";

  const codes = Array.from(sessions.keys()).sort();
  if (codes.length === 0) {
    const empty = document.createElement("div");
    empty.style.color = "var(--muted)";
    empty.style.fontSize = "13px";
    empty.textContent = "No sessions yet.";
    sessionListEl.appendChild(empty);
    return;
  }

  for (const code of codes) {
    const info = sessions.get(code);
    const row = document.createElement("div");
    row.className = "sessionItem" + (code === activeCode ? " active" : "");
    row.onclick = () => setActive(code);

    const left = document.createElement("div");
    left.className = "sessionLeft";
    left.innerHTML = `
      <div class="sessionCode">${escapeHtml(code)}</div>
      <div class="sessionSub">${info?.creator ? "Owner" : "Member"}</div>
    `;

    const btns = document.createElement("div");
    btns.className = "sessionBtns";

    const leaveSmall = document.createElement("button");
    leaveSmall.className = "iconBtn";
    leaveSmall.title = "Leave";
    leaveSmall.textContent = "⎋";
    leaveSmall.onclick = (e) => {
      e.stopPropagation();
      leaveSession(code);
    };

    btns.appendChild(leaveSmall);

    row.appendChild(left);
    row.appendChild(btns);
    sessionListEl.appendChild(row);
  }
}

function renderMembers(code) {
  const m = ensureMembers(code);
  memberListEl.innerHTML = "";
  const names = Array.from(m.values()).sort((a, b) => (a || "").localeCompare(b || ""));
  memberCountEl.textContent = String(names.length);

  if (!code || names.length === 0) {
    return;
  }
  for (const name of names) {
    const d = document.createElement("div");
    d.className = "memberRow";
    d.textContent = name;
    memberListEl.appendChild(d);
  }
}

function renderHistory(code) {
  logEl.innerHTML = "";
  const h = ensureHistory(code);

  // Build groups: consecutive messages by same sender within 5 minutes
  let lastSender = null;
  let lastTs = 0;
  let currentGroup = null;

  const flushGroup = () => {
    if (currentGroup) logEl.appendChild(currentGroup);
    currentGroup = null;
    lastSender = null;
    lastTs = 0;
  };

  for (const entry of h) {
    if (entry.kind === "system") {
      flushGroup();
      const wrap = document.createElement("div");
      wrap.className = "systemLine";
      wrap.innerHTML = `<div class="systemPill">${escapeHtml(entry.text)}</div>`;
      logEl.appendChild(wrap);
      continue;
    }

    const senderId = entry.from?.userId || "unknown";
    const isMe = me && senderId === me.id;

    const gapOk = Math.abs(entry.ts - lastTs) <= 5 * 60 * 1000;
    const sameSender = lastSender === senderId;

    if (!currentGroup || !sameSender || !gapOk) {
      flushGroup();
      currentGroup = document.createElement("div");
      currentGroup.className = "group" + (isMe ? " me" : "");
      const stack = document.createElement("div");
      stack.className = "bubbleStack";

      const header = document.createElement("div");
      header.className = "groupHeader";
      header.innerHTML = `<span class="name">${escapeHtml(fmtUser(entry.from))}</span><span class="time">${escapeHtml(
        timeStr(entry.ts)
      )}</span>`;
      stack.appendChild(header);

      currentGroup.appendChild(stack);
    }

    const stack = currentGroup.querySelector(".bubbleStack");
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = entry.text;
    stack.appendChild(bubble);

    if (entry.extraNode) {
      stack.appendChild(entry.extraNode);
    }

    lastSender = senderId;
    lastTs = entry.ts;
  }
  flushGroup();
  logEl.scrollTop = logEl.scrollHeight;
}

function pushEntry(code, entry) {
  ensureHistory(code).push(entry);
  if (activeCode === code) renderHistory(code);
}

function addSystem(code, text) {
  pushEntry(code, { kind: "system", ts: Date.now(), text });
}

function addMsg(code, from, ts, text, extraNode = null) {
  pushEntry(code, { kind: "msg", from, ts, text, extraNode });
}

// ---------- API helpers ----------
async function api(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || "Request failed");
  return j;
}

// ---------- WebSocket ----------
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/?token=${encodeURIComponent(token)}`);

  ws.onopen = () => {
    // Auto-join saved sessions (no UI spam).
    const saved = loadJoinedCodes();
    pendingAutoJoin = new Set(saved);
    for (const c of saved) ws.send(JSON.stringify({ type: "join_session", code: c }));
  };

  ws.onmessage = async (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }

    if (msg.type === "hello") {
      me = msg.user;
      meLine.textContent = me?.username ? `@${me.username}` : "…";

      // Restore active selection if still in joined list.
      const wanted = loadActive();
      if (wanted && loadJoinedCodes().includes(wanted)) setActive(wanted);
      else setActive(null);
      return;
    }

    if (msg.type === "error") {
      // Show errors in current session if possible, else as a global system pill.
      if (activeCode) addSystem(activeCode, msg.message || "Error");
      else {
        // If no active session, show briefly in header.
        sessionMetaEl.textContent = msg.message || "Error";
      }
      return;
    }

    if (msg.type === "members") {
      const code = msg.code;
      if (!code) return;
      const m = ensureMembers(code);
      m.clear();
      (msg.members || []).forEach((x) => {
        if (x?.userId) m.set(x.userId, x.username || x.userId);
      });
      if (code === activeCode) renderMembers(code);
      return;
    }

    if (msg.type === "presence") {
      const code = msg.code;
      if (!code) return;
      if (!sessions.has(code)) return;

      const m = ensureMembers(code);

      if (msg.event === "join") {
        m.set(msg.userId, msg.username);
        // Don't spam join/leave messages for yourself (esp. refresh).
        if (me && msg.userId !== me.id) addSystem(code, `${msg.username} joined.`);
      } else if (msg.event === "leave") {
        m.delete(msg.userId);
        if (me && msg.userId !== me.id) addSystem(code, `${msg.username} left.`);
      }

      if (code === activeCode) renderMembers(code);
      return;
    }

    if (msg.type === "session") {
      const code = msg.code;

      if (msg.event === "created" || msg.event === "joined") {
        sessions.set(code, { creator: !!msg.creator });
        ensureMembers(code);
        await ensureSessionKey(code); // derive key

        // persist joined list
        const joined = loadJoinedCodes();
        if (!joined.includes(code)) {
          joined.push(code);
          saveJoinedCodes(joined);
        }

        // Ensure history exists (fresh)
        if (!histories.has(code)) histories.set(code, []);

        // Selection logic:
        // - If user created a session: always switch to it and clear the view.
        // - If user explicitly joined: switch to it.
        // - If auto-joined on refresh: keep the previously selected session (if any).
        const wanted = loadActive();
        const isAuto = pendingAutoJoin.has(code);

        if (msg.event === "created") {
          requestedCreate = false;
          histories.set(code, []); // start clean
          setActive(code);
        } else if (requestedJoin === code) {
          requestedJoin = null;
          setActive(code);
        } else if (!activeCode) {
          // No active yet: prefer wanted.
          if (wanted && sessions.has(wanted)) setActive(wanted);
          else setActive(code);
        } else if (isAuto && wanted === code) {
          setActive(code);
        }

        pendingAutoJoin.delete(code);
        renderSessionList();
        return;
      }

      if (msg.event === "left") {
        dropSessionLocally(code);
        return;
      }

      if (msg.event === "ended") {
        dropSessionLocally(code);
        return;
      }

      return;
    }

    if (msg.type === "cipher") {
      const code = msg.code;
      if (!code) return;

      const key = await ensureSessionKey(code);
      try {
        if (msg.kind === "text") {
          const pt = await decryptBytes(key, msg.iv, msg.data);
          const text = new TextDecoder().decode(pt);
          addMsg(code, msg.from, msg.ts || Date.now(), text, null);
        } else if (msg.kind === "file") {
          const bytes = await decryptBytes(key, msg.iv, msg.data);
          const blob = new Blob([bytes], { type: msg.mime || "application/octet-stream" });
          const url = URL.createObjectURL(blob);

          const extra = document.createElement("div");
          extra.style.marginTop = "6px";
          extra.innerHTML = `<a href="${url}" download="${escapeHtml(msg.name || "file")}">Download ${escapeHtml(
            msg.name || "file"
          )}</a> <span style="color:var(--muted); font-size:12px;">(${Math.round(
            (msg.size || bytes.length) / 1024
          )} KB)</span>`;

          addMsg(code, msg.from, msg.ts || Date.now(), "Sent a file:", extra);
        }
      } catch {
        addSystem(code, "Couldn't decrypt a message.");
      }
      return;
    }
  };

  ws.onclose = () => {
    // Auto-reconnect (silent)
    setTimeout(connect, 800);
  };
  ws.onerror = () => {};
}

function dropSessionLocally(code) {
  sessions.delete(code);
  membersByCode.delete(code);
  sessionKeys.delete(code);
  histories.delete(code);

  const joined = loadJoinedCodes().filter((c) => c !== code);
  saveJoinedCodes(joined);

  if (activeCode === code) {
    setActive(joined[0] || null);
  } else {
    renderSessionList();
    if (activeCode) updateHeaderButtons();
  }
}

function updateHeaderButtons() {
  const has = !!activeCode;
  leaveBtn.disabled = !has;
  endBtn.disabled = !has || !sessions.get(activeCode)?.creator;
  msgBox.disabled = !has;
  sendBtn.disabled = !has;
  attachBtn.disabled = !has;
}

// ---------- actions ----------
createBtn.onclick = () => {
  requestedCreate = true;
  ws?.send(JSON.stringify({ type: "create_session" }));
};

joinBtn.onclick = () => showJoinModal(true);

leaveBtn.onclick = () => {
  if (activeCode) leaveSession(activeCode);
};

endBtn.onclick = () => {
  if (!activeCode) return;
  if (!sessions.get(activeCode)?.creator) return;
  ws?.send(JSON.stringify({ type: "end_session", code: activeCode }));
};

function leaveSession(code) {
  if (!code) return;
  ws?.send(JSON.stringify({ type: "leave_session", code }));
}

function showJoinModal(on) {
  joinModal.classList.toggle("hidden", !on);
  modalErr.classList.add("hidden");
  modalErr.textContent = "";
  if (on) {
    codeInput.value = "";
    codeInput.focus();
  }
}

cancelBtn.onclick = () => showJoinModal(false);
joinModal.addEventListener("click", (e) => {
  if (e.target === joinModal) showJoinModal(false);
});
confirmJoinBtn.onclick = () => {
  const code = codeInput.value.trim().toUpperCase();
  if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) {
    modalErr.textContent = "Invalid code format.";
    modalErr.classList.remove("hidden");
    return;
  }
  requestedJoin = code;
  ws?.send(JSON.stringify({ type: "join_session", code }));
  showJoinModal(false);
};

// Composer
sendBtn.onclick = sendText;
msgBox.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendText();
  }
});

async function sendText() {
  const text = msgBox.value.trim();
  if (!text) return;
  if (!activeCode) {
    sessionMetaEl.textContent = "Select a session first.";
    return;
  }
  if (!ws || ws.readyState !== 1) return;

  const key = await ensureSessionKey(activeCode);
  msgBox.value = "";
  const pt = new TextEncoder().encode(text);
  const { iv, data } = await encryptBytes(key, pt);
  ws.send(JSON.stringify({ type: "cipher", code: activeCode, kind: "text", iv, data }));
}

attachBtn.onclick = () => {
  if (activeCode) fileInput.click();
};

fileInput.onchange = async () => {
  const f = fileInput.files && fileInput.files[0];
  fileInput.value = "";
  if (!f || !activeCode || !ws || ws.readyState !== 1) return;

  const max = 2 * 1024 * 1024;
  if (f.size > max) {
    addSystem(activeCode, "File too large (max 2MB).");
    return;
  }

  const key = await ensureSessionKey(activeCode);
  const buf = new Uint8Array(await f.arrayBuffer());
  const { iv, data } = await encryptBytes(key, buf);
  ws.send(
    JSON.stringify({
      type: "cipher",
      code: activeCode,
      kind: "file",
      iv,
      data,
      name: f.name,
      mime: f.type || "application/octet-stream",
      size: f.size,
    })
  );
};

// Settings (password only)
settingsBtn.onclick = () => showSettings(true);
closeSettingsBtn.onclick = () => showSettings(false);
settingsModal.addEventListener("click", (e) => {
  if (e.target === settingsModal) showSettings(false);
});
function showSettings(on) {
  settingsModal.classList.toggle("hidden", !on);
  passErr.classList.add("hidden");
  passOk.classList.add("hidden");
}
savePassBtn.onclick = async () => {
  passErr.classList.add("hidden");
  passOk.classList.add("hidden");
  try {
    await api("/api/change_password", { currentPassword: curPass.value, newPassword: newPass.value });
    curPass.value = "";
    newPass.value = "";
    passOk.classList.remove("hidden");
  } catch (e) {
    passErr.textContent = e.message || "Failed.";
    passErr.classList.remove("hidden");
  }
};

// Logout
logoutBtn.onclick = async () => {
  try {
    await fetch("/api/logout", { method: "POST", headers: { Authorization: "Bearer " + token } });
  } catch {}
  localStorage.removeItem("diskord_token");
  localStorage.removeItem("diskord_joined");
  localStorage.removeItem("diskord_active");
  location.href = "/login";
};

connect();
