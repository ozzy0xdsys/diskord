const token = localStorage.getItem("diskord_token");
if (!token) location.href = "/login";

const el = (id) => document.getElementById(id);

const logEl = el("log");
const sessionPill = el("sessionPill");
const sessionHint = el("sessionHint");
const sessionList = el("sessionList");
const memberListEl = el("memberList");
const memberCountEl = el("memberCount");

const msgBox = el("msg");
const sendBtn = el("sendBtn");
const attachBtn = el("attachBtn");
const fileInput = el("file");
const createBtn = el("createBtn");
const joinBtn = el("joinBtn");
const leaveBtn = el("leaveBtn");
const endBtn = el("endBtn");
const logoutBtn = el("logoutBtn");

const settingsBtn = el("settingsBtn");
const meAvatar = el("meAvatar");

// Join modal
const joinModal = el("modal");
const codeInput = el("codeInput");
const modalErr = el("modalErr");

// Settings modal
const settingsModal = el("settingsModal");
const closeSettingsBtn = el("closeSettingsBtn");
const avatarFile = el("avatarFile");
const settingsAvatar = el("settingsAvatar");
const avatarErr = el("avatarErr");
const avatarOk = el("avatarOk");
const curPass = el("curPass");
const newPass = el("newPass");
const savePassBtn = el("savePassBtn");
const passErr = el("passErr");
const passOk = el("passOk");

let ws = null;
let me = null;
let myAvatar = null;

// code -> { creator:boolean }
const sessions = new Map();

// code -> CryptoKey
const sessionKeys = new Map();
const membersByCode = new Map(); // code -> Map(userId -> username)

// code -> array of rendered nodes (for quick switch)
const histories = new Map();

let activeCode = null;

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

// ---------- UI helpers ----------
function nowTime(ts) {
  const d = new Date(ts || Date.now());
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function escapeHtml(s) {
  return (s || "")
    .toString()
    .replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
}

function ensureHistory(code) {
  if (!histories.has(code)) histories.set(code, []);
  return histories.get(code);
}

function renderHistory(code) {
  logEl.innerHTML = "";
  const h = ensureHistory(code);
  for (const node of h) logEl.appendChild(node);
  logEl.scrollTop = logEl.scrollHeight;
}

function pushNode(code, node) {
  ensureHistory(code).push(node);
  // If currently viewing, attach immediately.
  if (activeCode === code) {
    logEl.appendChild(node);
    logEl.scrollTop = logEl.scrollHeight;
  }
}

function addSystem(code, text) {
  const div = document.createElement("div");
  div.className = "msg";
  div.innerHTML = `<div class="meta">${nowTime()} • system</div><div class="bubble">${escapeHtml(text)}</div>`;
  pushNode(code, div);
}

function addMessage(code, { from, ts, text, meMsg = false, extraNode = null }) {
  const div = document.createElement("div");
  div.className = "msg" + (meMsg ? " me" : "");
  div.innerHTML = `<div class="meta">${nowTime(ts)} • ${escapeHtml(from?.username || "unknown")}</div>`;
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = text || "";
  div.appendChild(bubble);
  if (extraNode) div.appendChild(extraNode);
  pushNode(code, div);
}

function setComposerEnabled(on) {
  msgBox.disabled = !on;
  sendBtn.disabled = !on;
  attachBtn.disabled = !on;
}

function updateTopbar() {
  const hasActive = !!activeCode;
  if (!hasActive) {
    sessionPill.textContent = "No session selected";
    sessionHint.textContent = "Create or join a session to start.";
  } else {
    sessionPill.textContent = `Session: ${activeCode}`;
    sessionHint.textContent = "";
  }

  const s = activeCode ? sessions.get(activeCode) : null;
  leaveBtn.disabled = !hasActive;
  endBtn.disabled = !(hasActive && s?.creator);
  setComposerEnabled(hasActive);
}


function ensureMembers(code){
  if(!membersByCode.has(code)) membersByCode.set(code, new Map());
  return membersByCode.get(code);
}
function renderMembers(){
  if(!activeCode){
    memberCountEl.textContent = "0";
    memberListEl.innerHTML = "";
    return;
  }
  const m = ensureMembers(activeCode);
  const arr = Array.from(m.entries()).map(([userId, username]) => ({ userId, username }));
  arr.sort((a,b)=>(a.username||"").localeCompare(b.username||""));
  memberCountEl.textContent = String(arr.length);
  memberListEl.innerHTML = arr.map(x => `
    <div class="memberItem">
      <div class="memberDot" aria-hidden="true"></div>
      <div class="memberName">${escapeHtml(x.username || x.userId)}</div>
    </div>
  `).join("");
}

function renderSessionsList() {
  sessionList.innerHTML = "";
  const codes = Array.from(sessions.keys()).sort();
  if (codes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "notice";
    empty.textContent = "No sessions yet.";
    sessionList.appendChild(empty);
    return;
  }

  for (const code of codes) {
    const s = sessions.get(code);
    const row = document.createElement("div");
    row.className = "sessionItem" + (code === activeCode ? " active" : "");

    const meta = document.createElement("div");
    meta.className = "sessionMeta";
    meta.innerHTML = `<div class="sessionCode">${escapeHtml(code)}</div><div class="sessionSub">${s?.creator ? "Creator" : "Joined"}</div>`;

    const leave = document.createElement("button");
    leave.className = "secondary miniBtn";
    leave.textContent = "Leave";
    leave.onclick = (e) => {
      e.stopPropagation();
      leaveSession(code);
    };

    row.appendChild(meta);
    row.appendChild(leave);
    row.onclick = () => setActive(code);

    sessionList.appendChild(row);
  }
}

function setActive(code) {
  activeCode = code;
  saveActive(code);
  updateTopbar();
  renderSessionsList();
  renderHistory(code);
}

function dropSessionLocally(code) {
  sessions.delete(code);
  sessionKeys.delete(code);
  histories.delete(code);
  membersByCode.delete(code);

  const codes = loadJoinedCodes().filter((c) => c !== code);
  saveJoinedCodes(codes);

  if (activeCode === code) {
    activeCode = null;
    const next = codes[0] || null;
    if (next) setActive(next);
    else {
      saveActive(null);
      logEl.innerHTML = "";
      updateTopbar();
    }
  }
  renderSessionsList();
  updateTopbar();
}

// ---------- crypto (per session code) ----------
async function deriveSessionKey(code) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(code), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("diskord-salt-v1"), iterations: 120000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function b64FromBytes(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}
function bytesFromB64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return { iv: b64FromBytes(iv), data: b64FromBytes(new Uint8Array(ct)) };
}
async function decryptBytes(key, ivB64, dataB64) {
  const iv = bytesFromB64(ivB64);
  const data = bytesFromB64(dataB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new Uint8Array(pt);
}

// ---------- websocket ----------
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/?token=${encodeURIComponent(token)}`);

  ws.onopen = () => {
    // silently
  };
  ws.onclose = () => {
    // silently
  };
  ws.onerror = () => {
    if (activeCode) addSystem(activeCode, "WebSocket error.");
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
      myAvatar = msg.avatar || null;
      el("meLine").textContent = `Signed in as ${me.username}`;
      setAvatarImg(meAvatar, myAvatar);
      setAvatarImg(settingsAvatar, myAvatar);

      // Auto-rejoin saved sessions on refresh
      const saved = loadJoinedCodes();
      for (const code of saved) {
        ws.send(JSON.stringify({ type: "join_session", code }));
      }
      // restore active if possible
      const wanted = loadActive();
      if (wanted && saved.includes(wanted)) {
        // We'll set active once we get the join ack.
      }
      return;
    }

    if (msg.type === "error") {
      const c = activeCode || (loadJoinedCodes()[0] || "");
      if (c) addSystem(c, msg.message || "Error");
      return;
    }

    if (msg.type === "presence") {
      const code = msg.code;
      if (!code || !sessions.has(code)) return;
      const m = ensureMembers(code);
      if (msg.event === "join") {
        m.set(msg.userId, msg.username);
        addSystem(code, `${msg.username} joined.`);
      }
      if (msg.event === "leave") {
        m.delete(msg.userId);
        addSystem(code, `${msg.username} left.`);
      }
      if (code === activeCode) renderMembers();
      return;
    }
    if (msg.type === "members") {
      const code = msg.code;
      if (!code) return;
      const m = ensureMembers(code);
      m.clear();
      (msg.members || []).forEach(x => {
        if (x && x.userId) m.set(x.userId, x.username || x.userId);
      });
      if (code === activeCode) renderMembers();
      return;
    }


    if (msg.type === "session") {
      const code = msg.code;

      if (msg.event === "created" || msg.event === "joined") {
        sessions.set(code, { creator: !!msg.creator });
        ensureMembers(code);
        if (!sessionKeys.has(code)) sessionKeys.set(code, await deriveSessionKey(code));
        ensureHistory(code);

        // persist joined list
        const joined = loadJoinedCodes();
        if (!joined.includes(code)) {
          joined.push(code);
          saveJoinedCodes(joined);
        }

        // first session or restoring active
        const wanted = loadActive();
        if (!activeCode) {
          setActive(wanted && sessions.has(wanted) ? wanted : code);
        } else if (wanted === code && activeCode !== wanted) {
          setActive(wanted);
        }

        renderSessionsList();
        updateTopbar();
        addSystem(code, `In ${code}. Share the code to invite others.`);
        return;
      }

      if (msg.event === "left") {
        if (histories.has(code)) addSystem(code, "You left this session.");
        dropSessionLocally(code);
        return;
      }

      if (msg.event === "ended") {
        // Session ended for everyone.
        if (histories.has(code)) addSystem(code, "Session ended.");
        dropSessionLocally(code);
        return;
      }

      return;
    }

    if (msg.type === "cipher") {
      const code = msg.code;
      const key = sessionKeys.get(code);
      if (!code || !key) return;
      try {
        if (msg.kind === "text") {
          const pt = await decryptBytes(key, msg.iv, msg.data);
          const text = new TextDecoder().decode(pt);
          addMessage(code, { from: msg.from, ts: msg.ts, text, meMsg: msg.from?.userId === me?.id });
        } else if (msg.kind === "file") {
          const bytes = await decryptBytes(key, msg.iv, msg.data);
          const blob = new Blob([bytes], { type: msg.mime || "application/octet-stream" });
          const url = URL.createObjectURL(blob);
          const extra = document.createElement("div");
          extra.style.marginTop = "6px";
          extra.innerHTML = `<a href="${url}" download="${escapeHtml(msg.name || "file")}">Download ${escapeHtml(
            msg.name || "file"
          )}</a> <small>(${Math.round((msg.size || bytes.length) / 1024)} KB)</small>`;
          addMessage(code, {
            from: msg.from,
            ts: msg.ts,
            text: "Sent a file:",
            meMsg: msg.from?.userId === me?.id,
            extraNode: extra,
          });
        }
      } catch {
        addSystem(code, "Couldn't decrypt a message (wrong code?)");
      }
      return;
    }
  };
}

connect();

// ---------- session actions ----------
createBtn.onclick = () => ws?.send(JSON.stringify({ type: "create_session" }));
joinBtn.onclick = () => showJoinModal(true);
leaveBtn.onclick = () => {
  if (activeCode) leaveSession(activeCode);
};
endBtn.onclick = () => {
  if (!activeCode) return;
  const s = sessions.get(activeCode);
  if (!s?.creator) return;
  ws?.send(JSON.stringify({ type: "end_session", code: activeCode }));
};

function leaveSession(code) {
  if (!code) return;
  ws?.send(JSON.stringify({ type: "leave_session", code }));
}

// ---------- join modal ----------
function showJoinModal(on) {
  joinModal.classList.toggle("hidden", !on);
  modalErr.classList.add("hidden");
  if (on) {
    codeInput.value = "";
    codeInput.focus();
  }
}
el("cancelBtn").onclick = () => showJoinModal(false);
el("confirmJoinBtn").onclick = () => {
  const code = codeInput.value.trim().toUpperCase();
  if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) {
    modalErr.textContent = "Invalid code format.";
    modalErr.classList.remove("hidden");
    return;
  }
  ws?.send(JSON.stringify({ type: "join_session", code }));
  showJoinModal(false);
};

// ---------- composer ----------
sendBtn.onclick = sendText;
msgBox.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendText();
  }
});

async function sendText() {
  const text = msgBox.value.trim();
  if (!text || !activeCode || !ws) return;
  const key = sessionKeys.get(activeCode);
  if (!key) return;

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
  if (!f || !activeCode || !ws) return;
  const key = sessionKeys.get(activeCode);
  if (!key) return;

  const max = 2 * 1024 * 1024;
  if (f.size > max) {
    addSystem(activeCode, "File too large (max 2MB). ");
    return;
  }

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

// ---------- settings ----------
settingsBtn.onclick = () => showSettings(true);
closeSettingsBtn.onclick = () => showSettings(false);

function showSettings(on) {
  settingsModal.classList.toggle("hidden", !on);
  if (on) {
    avatarErr.classList.add("hidden");
    avatarOk.classList.add("hidden");
    passErr.classList.add("hidden");
    passOk.classList.add("hidden");
  }
}

function setAvatarImg(imgEl, dataUrl) {
  if (!imgEl) return;
  if (!dataUrl) {
    imgEl.removeAttribute("src");
    imgEl.style.opacity = "0.7";
  } else {
    imgEl.src = dataUrl;
    imgEl.style.opacity = "1";
  }
}

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + token,
    },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

avatarFile.onchange = async () => {
  const file = avatarFile.files && avatarFile.files[0];
  avatarFile.value = "";
  avatarErr.classList.add("hidden");
  avatarOk.classList.add("hidden");
  if (!file) return;

  try {
    const dataUrl = await resizeImageToDataUrl(file, 256);
    await api("/api/avatar", { dataUrl });
    myAvatar = dataUrl;
    setAvatarImg(meAvatar, myAvatar);
    setAvatarImg(settingsAvatar, myAvatar);
    avatarOk.classList.remove("hidden");
  } catch (e) {
    avatarErr.textContent = e.message || "Couldn't save avatar.";
    avatarErr.classList.remove("hidden");
  }
};

savePassBtn.onclick = async () => {
  passErr.classList.add("hidden");
  passOk.classList.add("hidden");
  try {
    const cur = curPass.value;
    const next = newPass.value;
    if (!cur || !next) throw new Error("Fill both password fields.");
    await api("/api/change_password", { currentPassword: cur, newPassword: next });
    curPass.value = "";
    newPass.value = "";
    passOk.classList.remove("hidden");
  } catch (e) {
    passErr.textContent = e.message || "Couldn't change password.";
    passErr.classList.remove("hidden");
  }
};

async function resizeImageToDataUrl(file, maxSize) {
  const blobUrl = URL.createObjectURL(file);
  try {
    const img = await new Promise((resolve, reject) => {
      const i = new Image();
      i.onload = () => resolve(i);
      i.onerror = () => reject(new Error("Invalid image."));
      i.src = blobUrl;
    });

    const w = img.naturalWidth || img.width;
    const h = img.naturalHeight || img.height;
    if (!w || !h) throw new Error("Invalid image.");

    const scale = Math.min(1, maxSize / Math.max(w, h));
    const nw = Math.max(1, Math.round(w * scale));
    const nh = Math.max(1, Math.round(h * scale));

    const canvas = document.createElement("canvas");
    canvas.width = nw;
    canvas.height = nh;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, nw, nh);

    // Prefer jpeg for size
    const dataUrl = canvas.toDataURL("image/jpeg", 0.82);
    if (dataUrl.length > 250000) throw new Error("Image still too large after resize.");
    return dataUrl;
  } finally {
    URL.revokeObjectURL(blobUrl);
  }
}

// ---------- logout ----------
logoutBtn.onclick = async () => {
  try {
    await fetch("/api/logout", { method: "POST", headers: { Authorization: "Bearer " + token } });
  } catch {}
  localStorage.removeItem("diskord_token");
  localStorage.removeItem("diskord_joined");
  localStorage.removeItem("diskord_active");
  location.href = "/login";
};

// Close modals on ESC
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  showJoinModal(false);
  showSettings(false);
});
