const $ = (id) => document.getElementById(id);

const authView = $("authView");
const appView = $("appView");
const userPill = $("userPill");
const meLabel = $("meLabel");
const meName = $("meName");

const usernameEl = $("username");
const passwordEl = $("password");
const authBtn = $("authBtn");
const logoutBtn = $("logoutBtn");

const joinBtn = $("joinBtn");
const createBtn = $("createBtn");
const sessionsList = $("sessionsList");

const sessionCodeEl = $("sessionCode");
const sessionOwnerEl = $("sessionOwner");
const memberCountEl = $("memberCount");
const endBtn = $("endBtn");

const messagesEl = $("messages");
const msgInput = $("msgInput");
const sendBtn = $("sendBtn");

const attachBtn = $("attachBtn");
const fileInput = $("fileInput");

const modalBack = $("modalBack");
const codeInput = $("codeInput");
const cancelJoin = $("cancelJoin");
const confirmJoin = $("confirmJoin");

const toast = $("toast");

let state = {
  token: null,
  username: null,
  currentSession: null, // { code, owner }
  ws: null,
  key: null, // CryptoKey for E2EE (derived from session code)
};

function showToast(text) {
  toast.textContent = text;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), 2600);
}

function setAuthed(on) {
  authView.classList.toggle("hidden", on);
  appView.classList.toggle("hidden", !on);
  userPill.classList.toggle("hidden", !on);
}

function api(path, opts={}) {
  return fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(opts.headers || {}),
      ...(state.token ? { "Authorization": `Bearer ${state.token}` } : {})
    }
  });
}

// --- E2EE: derive AES-GCM key from session code (shared secret) ---
// Note: This is a simple approach. Anyone with the session code can decrypt.
// If you want stronger security, add a "session passphrase" prompt and derive from that.
async function deriveKeyFromCode(code) {
  const enc = new TextEncoder();
  const salt = enc.encode("diskord:salt:v1");
  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(code),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function unb64(s) {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

async function encryptJson(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, state.key, plain);
  return JSON.stringify({ v:1, iv: b64(iv), ct: b64(ct) });
}

async function decryptJson(payload) {
  const { v, iv, ct } = JSON.parse(payload);
  if (v !== 1) throw new Error("bad_version");
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(unb64(iv)) },
    state.key,
    unb64(ct)
  );
  const plain = new TextDecoder().decode(plainBuf);
  return JSON.parse(plain);
}

// --- UI helpers ---
function clearMessages() { messagesEl.innerHTML = ""; }
function addSystem(text) {
  const el = document.createElement("div");
  el.className = "msg";
  el.innerHTML = `
    <div class="top"><div class="sender">system</div><div class="time">—</div></div>
    <div class="body muted"></div>
  `;
  el.querySelector(".body").textContent = text;
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addMessage({ sender, created_at, kind, payload, meta }) {
  const mine = sender === state.username;
  const el = document.createElement("div");
  el.className = "msg" + (mine ? " mine" : "");
  const t = created_at ? new Date(created_at).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}) : "—";
  el.innerHTML = `
    <div class="top">
      <div class="sender"></div>
      <div class="time"></div>
    </div>
    <div class="body"></div>
  `;
  el.querySelector(".sender").textContent = sender;
  el.querySelector(".time").textContent = t;

  if (kind === "file") {
    const body = el.querySelector(".body");
    const pill = document.createElement("div");
    pill.className = "file-pill";
    const a = document.createElement("a");
    a.href = "#";
    a.textContent = meta?.filename || "file";
    const small = document.createElement("span");
    small.className = "muted small";
    small.textContent = meta?.size ? `${Math.round(meta.size/1024)} KB` : "";
    pill.appendChild(a);
    pill.appendChild(small);
    body.appendChild(pill);

    a.addEventListener("click", async (e) => {
      e.preventDefault();
      try{
        const obj = await decryptJson(payload); // { name, type, dataB64 }
        const bytes = Uint8Array.from(atob(obj.dataB64), c => c.charCodeAt(0));
        const blob = new Blob([bytes], { type: obj.type || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const dl = document.createElement("a");
        dl.href = url;
        dl.download = obj.name || "file";
        document.body.appendChild(dl);
        dl.click();
        dl.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      }catch(err){
        showToast("Couldn't decrypt file (wrong code?)");
      }
    });
  } else {
    (async () => {
      try{
        const obj = await decryptJson(payload); // { text }
        el.querySelector(".body").textContent = obj.text || "";
      }catch{
        el.querySelector(".body").textContent = "[Could not decrypt message]";
        el.querySelector(".body").classList.add("muted");
      }
    })();
  }

  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function setSessionUI(session) {
  if (!session) {
    sessionCodeEl.textContent = "—";
    sessionOwnerEl.textContent = "—";
    memberCountEl.textContent = "0";
    endBtn.classList.add("hidden");
    return;
  }
  sessionCodeEl.textContent = session.code;
  sessionOwnerEl.textContent = session.owner;
  endBtn.classList.toggle("hidden", session.owner !== state.username);
}

function openJoinModal() {
  codeInput.value = "";
  modalBack.classList.remove("hidden");
  codeInput.focus();
}
function closeJoinModal() {
  modalBack.classList.add("hidden");
}

// --- Auth ---
authBtn.addEventListener("click", async () => {
  const username = usernameEl.value.trim();
  const password = passwordEl.value;
  const res = await api("/api/auth", { method:"POST", body: JSON.stringify({ username, password }) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return showToast(data.error || "Auth failed");
  state.token = data.token;
  state.username = data.username;
  meLabel.textContent = data.username;
  meName.textContent = data.username;
  setAuthed(true);
  showToast(data.created ? "Account created" : "Logged in");
  await refreshSessions();
});

logoutBtn.addEventListener("click", () => {
  cleanupWs();
  state.token = null;
  state.username = null;
  state.currentSession = null;
  state.key = null;
  setSessionUI(null);
  clearMessages();
  setAuthed(false);
  showToast("Logged out");
});

// --- Sessions ---
async function refreshSessions() {
  const res = await api("/api/sessions");
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return;
  sessionsList.innerHTML = "";
  for (const s of data.sessions || []) {
    const row = document.createElement("div");
    row.className = "session-item";
    row.innerHTML = `
      <div>
        <div class="code">${s.code}</div>
        <div class="owner">Owner: ${s.owner}</div>
      </div>
      <div class="muted small">${new Date(s.created_at).toLocaleDateString()}</div>
    `;
    row.addEventListener("click", () => joinSession(s.code));
    sessionsList.appendChild(row);
  }
}

createBtn.addEventListener("click", async () => {
  const res = await api("/api/sessions", { method:"POST", body: JSON.stringify({}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return showToast(data.error || "Failed to create");
  await refreshSessions();
  await joinSession(data.code);
  showToast(`Created ${data.code}`);
});

joinBtn.addEventListener("click", openJoinModal);
cancelJoin.addEventListener("click", closeJoinModal);
confirmJoin.addEventListener("click", () => {
  const code = codeInput.value.trim().toUpperCase();
  closeJoinModal();
  joinSession(code);
});
modalBack.addEventListener("click", (e) => {
  if (e.target === modalBack) closeJoinModal();
});

async function joinSession(code) {
  code = String(code || "").trim().toUpperCase();
  if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) return showToast("Bad code format");
  cleanupWs();
  clearMessages();
  addSystem("Joining…");

  // derive E2EE key
  state.key = await deriveKeyFromCode(code);

  // load session meta via messages endpoint (it will 404 if session doesn't exist)
  const res = await api(`/api/sessions/${encodeURIComponent(code)}/messages`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    state.key = null;
    addSystem("");
    clearMessages();
    return showToast(data.error === "not_found" ? "Session not found" : (data.error || "Join failed"));
  }

  // session owner isn't returned here; we'll get it from websocket hello_ok
  state.currentSession = { code, owner: "…" };
  setSessionUI(state.currentSession);

  // render history
  clearMessages();
  for (const m of data.messages || []) addMessage(m);

  connectWs(code);
}

function cleanupWs() {
  if (state.ws) {
    try { state.ws.close(1000, "switch"); } catch {}
  }
  state.ws = null;
}

function wsUrl() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}`;
}

function connectWs(code) {
  const ws = new WebSocket(wsUrl());
  state.ws = ws;

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type:"hello", token: state.token, code }));
  });

  ws.addEventListener("message", async (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }

    if (msg.type === "hello_ok") {
      state.currentSession.owner = msg.owner;
      setSessionUI(state.currentSession);
      memberCountEl.textContent = String(msg.members || 0);
      addSystem(`Connected to ${msg.code}`);
      return;
    }

    if (msg.type === "member_join") {
      memberCountEl.textContent = String(msg.members || 0);
      addSystem(`${msg.username} joined`);
      return;
    }
    if (msg.type === "member_leave") {
      memberCountEl.textContent = String(msg.members || 0);
      addSystem(`${msg.username} left`);
      return;
    }
    if (msg.type === "session_ended") {
      addSystem("Session ended by owner. History cleared.");
      state.currentSession = null;
      state.key = null;
      setSessionUI(null);
      cleanupWs();
      await refreshSessions();
      return;
    }
    if (msg.type === "message") {
      addMessage(msg.message);
      return;
    }
  });

  ws.addEventListener("close", (ev) => {
    if (state.currentSession) addSystem("Disconnected.");
    // If session ended, server closes with 4001; UI already handles via message
    console.debug("ws closed", ev.code, ev.reason);
  });
}

// --- Send messages ---
async function sendText() {
  const text = msgInput.value;
  if (!text.trim()) return;
  if (!state.ws || state.ws.readyState !== 1) return showToast("Not connected");
  if (!state.key) return showToast("No E2EE key");

  const payload = await encryptJson({ text });
  state.ws.send(JSON.stringify({ type:"send", kind:"text", payload, meta:{} }));
  msgInput.value = "";
}

sendBtn.addEventListener("click", sendText);
msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendText();
  }
});

attachBtn.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  fileInput.value = "";
  if (!file) return;
  if (!state.ws || state.ws.readyState !== 1) return showToast("Not connected");
  if (!state.key) return showToast("No E2EE key");
  if (file.size > 8 * 1024 * 1024) return showToast("Max file size is 8MB");

  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const dataB64 = btoa(String.fromCharCode(...bytes));
  const payload = await encryptJson({ name: file.name, type: file.type, dataB64 });

  const meta = { filename: file.name, size: file.size, mime: file.type };
  state.ws.send(JSON.stringify({ type:"send", kind:"file", payload, meta }));
  showToast("File sent (encrypted)");
});

// End session
endBtn.addEventListener("click", async () => {
  const code = state.currentSession?.code;
  if (!code) return;
  if (!confirm("End session? This deletes all encrypted messages/files on the server.")) return;
  const res = await api(`/api/sessions/${encodeURIComponent(code)}`, { method:"DELETE" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return showToast(data.error || "Failed to end");
  // session_ended will come via ws broadcast
});

// Initial: if token persisted
(function init(){
  const saved = localStorage.getItem("diskord_token");
  const user = localStorage.getItem("diskord_user");
  if (saved && user) {
    state.token = saved;
    state.username = user;
    meLabel.textContent = user;
    meName.textContent = user;
    setAuthed(true);
    refreshSessions();
  } else {
    setAuthed(false);
  }
})();

// Persist token on change
const origSetAuthed = setAuthed;
setAuthed = function(on){
  origSetAuthed(on);
  if (on && state.token && state.username) {
    localStorage.setItem("diskord_token", state.token);
    localStorage.setItem("diskord_user", state.username);
  } else {
    localStorage.removeItem("diskord_token");
    localStorage.removeItem("diskord_user");
  }
};
