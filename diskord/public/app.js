const token = localStorage.getItem("diskord_token");
if(!token) location.href="/login";

const el = (id)=>document.getElementById(id);
const logEl = el("log");
const sessionPill = el("sessionPill");
const msgBox = el("msg");
const sendBtn = el("sendBtn");
const attachBtn = el("attachBtn");
const fileInput = el("file");
const endBtn = el("endBtn");

let ws = null;
let me = null;
let sessionCode = null;
let isCreator = false;
let sessionKey = null;

function nowTime(ts){
  const d = new Date(ts || Date.now());
  return d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
}
function escapeHtml(s){
  return (s||"").toString().replace(/[&<>"']/g, c=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[c]));
}
function addSystem(text){
  const div = document.createElement("div");
  div.className = "msg";
  div.innerHTML = `<div class="meta">${nowTime()} • system</div><div class="bubble">${escapeHtml(text)}</div>`;
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}
function addMessage({ from, ts, text, meMsg=false, extraNode=null }){
  const div = document.createElement("div");
  div.className = "msg" + (meMsg ? " me" : "");
  div.innerHTML = `<div class="meta">${nowTime(ts)} • ${escapeHtml(from?.username || "unknown")}</div>`;
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = text || "";
  div.appendChild(bubble);
  if(extraNode) div.appendChild(extraNode);
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}
function setUiForSession(on){
  msgBox.disabled = !on;
  sendBtn.disabled = !on;
  attachBtn.disabled = !on;
}

// ---- crypto ----
async function deriveSessionKey(code){
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(code), { name:"PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt: enc.encode("diskord-salt-v1"), iterations: 120000, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
  );
}
function b64FromBytes(bytes){
  let bin = "";
  const chunk = 0x8000;
  for(let i=0;i<bytes.length;i+=chunk){
    bin += String.fromCharCode(...bytes.subarray(i,i+chunk));
  }
  return btoa(bin);
}
function bytesFromB64(b64){
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function encryptBytes(key, bytes){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, bytes);
  return { iv: b64FromBytes(iv), data: b64FromBytes(new Uint8Array(ct)) };
}
async function decryptBytes(key, ivB64, dataB64){
  const iv = bytesFromB64(ivB64);
  const data = bytesFromB64(dataB64);
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, data);
  return new Uint8Array(pt);
}

// ---- websocket ----
function connect(){
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/?token=${encodeURIComponent(token)}`);

  ws.onopen = () => addSystem("Connected.");
  ws.onclose = () => addSystem("Disconnected.");
  ws.onerror = () => addSystem("WebSocket error.");

  ws.onmessage = async (ev) => {
    let msg;
    try{ msg = JSON.parse(ev.data); }catch{ return; }

    if(msg.type === "hello"){
      me = msg.user;
      el("meLine").textContent = `Signed in as ${me.username}`;
      return;
    }
    if(msg.type === "error"){
      addSystem(msg.message || "Error");
      return;
    }
    if(msg.type === "presence"){
      if(!sessionCode) return;
      if(msg.event === "join") addSystem(`${msg.username} joined.`);
      if(msg.event === "leave") addSystem(`${msg.username} left.`);
      return;
    }
    if(msg.type === "session"){
      if(msg.event === "created" || msg.event === "joined"){
        sessionCode = msg.code;
        isCreator = !!msg.creator;
        endBtn.classList.toggle("hidden", !isCreator);
        sessionPill.textContent = `Session: ${sessionCode}`;
        setUiForSession(true);
        sessionKey = await deriveSessionKey(sessionCode);
        addSystem(`You are in ${sessionCode}. Share the code to invite others.`);
      }
      if(msg.event === "ended"){
        addSystem("Session ended.");
        sessionCode = null;
        isCreator = false;
        sessionKey = null;
        endBtn.classList.add("hidden");
        sessionPill.textContent = "No session";
        setUiForSession(false);
      }
      return;
    }
    if(msg.type === "cipher"){
      if(!sessionKey) return;
      try{
        if(msg.kind === "text"){
          const pt = await decryptBytes(sessionKey, msg.iv, msg.data);
          const text = new TextDecoder().decode(pt);
          addMessage({ from: msg.from, ts: msg.ts, text, meMsg: msg.from?.userId === me?.id });
        }else if(msg.kind === "file"){
          const bytes = await decryptBytes(sessionKey, msg.iv, msg.data);
          const blob = new Blob([bytes], { type: msg.mime || "application/octet-stream" });
          const url = URL.createObjectURL(blob);
          const extra = document.createElement("div");
          extra.style.marginTop = "6px";
          extra.innerHTML = `<a href="${url}" download="${escapeHtml(msg.name || "file")}">Download ${escapeHtml(msg.name || "file")}</a> <small>(${Math.round((msg.size||bytes.length)/1024)} KB)</small>`;
          addMessage({ from: msg.from, ts: msg.ts, text: "Sent a file:", meMsg: msg.from?.userId === me?.id, extraNode: extra });
        }
      }catch{
        addSystem("Couldn't decrypt a message (wrong code?)");
      }
      return;
    }
  };
}
connect();

// ---- UI ----
el("createBtn").onclick = () => ws?.send(JSON.stringify({ type:"create_session" }));
el("joinBtn").onclick = () => showModal(true);
endBtn.onclick = () => ws?.send(JSON.stringify({ type:"end_session" }));

el("logoutBtn").onclick = async () => {
  try{ await fetch("/api/logout", { method:"POST", headers:{ "Authorization":"Bearer " + token }}); }catch{}
  localStorage.removeItem("diskord_token");
  location.href="/login";
};

function showModal(on){
  el("modal").classList.toggle("hidden", !on);
  el("modalErr").classList.add("hidden");
  if(on){ el("codeInput").value = ""; el("codeInput").focus(); }
}
el("cancelBtn").onclick = () => showModal(false);
el("confirmJoinBtn").onclick = () => {
  const code = el("codeInput").value.trim().toUpperCase();
  if(!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)){
    const er = el("modalErr");
    er.textContent = "Invalid code format.";
    er.classList.remove("hidden");
    return;
  }
  ws?.send(JSON.stringify({ type:"join_session", code }));
  showModal(false);
};

sendBtn.onclick = sendText;
msgBox.addEventListener("keydown", (e)=>{
  if(e.key==="Enter" && !e.shiftKey){
    e.preventDefault();
    sendText();
  }
});

async function sendText(){
  const text = msgBox.value.trim();
  if(!text || !sessionKey || !ws) return;
  msgBox.value = "";
  const pt = new TextEncoder().encode(text);
  const { iv, data } = await encryptBytes(sessionKey, pt);
  ws.send(JSON.stringify({ type:"cipher", kind:"text", iv, data }));
}

attachBtn.onclick = () => { if(sessionKey) fileInput.click(); };
fileInput.onchange = async () => {
  const f = fileInput.files && fileInput.files[0];
  fileInput.value = "";
  if(!f || !sessionKey || !ws) return;

  const max = 2 * 1024 * 1024;
  if(f.size > max){ addSystem("File too large (max 2MB)."); return; }

  const buf = new Uint8Array(await f.arrayBuffer());
  const { iv, data } = await encryptBytes(sessionKey, buf);
  ws.send(JSON.stringify({ type:"cipher", kind:"file", iv, data, name:f.name, mime:f.type||"application/octet-stream", size:f.size }));
};
