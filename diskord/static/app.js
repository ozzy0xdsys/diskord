(() => {
  const cfg = window.DISKORD;

  const $messages = document.getElementById("messages");
  const $text = document.getElementById("text");
  const $send = document.getElementById("send");
  const $conn = document.getElementById("connState");
  const $chatList = document.getElementById("chatList");
  const $topTitle = document.getElementById("topTitle");

  const $attachBtn = document.getElementById("attachBtn");
  const $file = document.getElementById("file");
  const $fileChip = document.getElementById("fileChip");

  const $inviteBtn = document.getElementById("inviteBtn");
  const $leaveBtn = document.getElementById("leaveBtn");
  const $kickBtn = document.getElementById("kickBtn");

  const $friendsList = document.getElementById("friendsList");
  const $membersPanel = document.getElementById("membersPanel");
  const $membersList = document.getElementById("membersList");

  const $ctx = document.getElementById("ctx");

  let currentId = cfg.selected_id;
  let socket = null;
  let currentMeta = null; // {type, owner_id, members}
  let lastCtxTarget = null;

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------- helpers ----------
  function b64u(buf){
    const bytes = new Uint8Array(buf);
    let s = "";
    for(const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
  function unb64u(s){
    s = s.replace(/-/g,'+').replace(/_/g,'/');
    while(s.length%4) s+='=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
    return bytes.buffer;
  }
  function formPost(url, obj){
    const fd = new FormData();
    for(const [k,v] of Object.entries(obj)) fd.append(k, v);
    return fetch(url, {method:"POST", body: fd});
  }
  function hideCtx(){ $ctx.hidden = true; $ctx.innerHTML=""; lastCtxTarget=null; }
  function showCtx(x,y, items){
    $ctx.innerHTML = "";
    for(const it of items){
      if(it.type==="sep"){
        const sep=document.createElement("div");
        sep.className="ctxSep";
        $ctx.appendChild(sep);
        continue;
      }
      const d=document.createElement("div");
      d.className="ctxItem" + (it.danger ? " danger":"");
      d.textContent = it.label;
      d.addEventListener("click", async ()=>{
        hideCtx();
        try{ await it.onClick(); }catch(e){ alert(e?.message||"Action failed"); }
      });
      $ctx.appendChild(d);
    }
    $ctx.hidden = false;
    const pad=8;
    const rect = $ctx.getBoundingClientRect();
    const maxX = window.innerWidth - rect.width - pad;
    const maxY = window.innerHeight - rect.height - pad;
    $ctx.style.left = Math.max(pad, Math.min(x, maxX)) + "px";
    $ctx.style.top  = Math.max(pad, Math.min(y, maxY)) + "px";
  }

  // ---------- E2EE key wrap ----------
  async function deriveWrapKeyFromPassword(password){
    const salt = enc.encode("diskord-wrap:" + cfg.username);
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"PBKDF2", salt, iterations: 200000, hash:"SHA-256"},
      keyMaterial,
      {name:"AES-GCM", length: 256},
      false,
      ["encrypt","decrypt"]
    );
  }

  async function loadOrCreateIdentity(){
    const saved = localStorage.getItem("diskord_id_priv");
    const pw = sessionStorage.getItem("diskord_last_pw") || "";
    const wrapKey = pw ? await deriveWrapKeyFromPassword(pw) : null;

    if(saved && wrapKey){
      const blob = JSON.parse(saved);
      if(blob.raw){
        const priv = await crypto.subtle.importKey("jwk", blob.raw, {name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey","deriveBits"]);
        const pubJwk = JSON.parse(localStorage.getItem("diskord_id_pub") || "null");
        if(pubJwk){
          await fetch("/api/me/pubkey", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({pubkey_jwk: JSON.stringify(pubJwk)})}).catch(()=>{});
        }
        return {priv, pubJwk, wrapKey};
      }

      const privJwk = JSON.parse(dec.decode(await crypto.subtle.decrypt(
        {name:"AES-GCM", iv: new Uint8Array(unb64u(blob.nonce))},
        wrapKey,
        unb64u(blob.ct)
      )));
      const priv = await crypto.subtle.importKey("jwk", privJwk, {name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey","deriveBits"]);
      const pubJwk = JSON.parse(localStorage.getItem("diskord_id_pub") || "null");
      if(pubJwk){
        await fetch("/api/me/pubkey", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({pubkey_jwk: JSON.stringify(pubJwk)})}).catch(()=>{});
      }
      return {priv, pubJwk, wrapKey};
    }

    const kp = await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey","deriveBits"]);
    const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);

    localStorage.setItem("diskord_id_pub", JSON.stringify(pubJwk));

    if(wrapKey){
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv: nonce}, wrapKey, enc.encode(JSON.stringify(privJwk)));
      localStorage.setItem("diskord_id_priv", JSON.stringify({nonce: b64u(nonce), ct: b64u(ct)}));
    } else {
      localStorage.setItem("diskord_id_priv", JSON.stringify({raw: privJwk}));
    }

    await fetch("/api/me/pubkey", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({pubkey_jwk: JSON.stringify(pubJwk)})}).catch(()=>{});
    return {priv: kp.privateKey, pubJwk, wrapKey};
  }

  const convoKeys = new Map();

  async function getConvoKey(convoId){
    if(convoKeys.has(convoId)) return convoKeys.get(convoId);

    const r = await fetch(`/api/conversations/${encodeURIComponent(convoId)}/key`);
    const j = await r.json();
    if(!j.wrapped_key) return null;

    const pw = sessionStorage.getItem("diskord_last_pw") || "";
    if(!pw) return null;

    const wrapKey = await deriveWrapKeyFromPassword(pw);
    const raw = await crypto.subtle.decrypt({name:"AES-GCM", iv: new Uint8Array(unb64u(j.nonce))}, wrapKey, unb64u(j.wrapped_key));
    const aes = await crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
    convoKeys.set(convoId, aes);
    return aes;
  }

  async function ensureConvoKey(convoId){
    let k = await getConvoKey(convoId);
    if(k) return k;

    const pw = sessionStorage.getItem("diskord_last_pw") || "";
    if(!pw) return null;
    const wrapKey = await deriveWrapKeyFromPassword(pw);

    const raw = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv: nonce}, wrapKey, raw);

    await fetch(`/api/conversations/${encodeURIComponent(convoId)}/keys`, {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({keys:[{user_id: cfg.user_id, wrapped_key: b64u(ct), nonce: b64u(nonce)}]})
    }).catch(()=>{});

    const aes = await crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
    convoKeys.set(convoId, aes);
    return aes;
  }

  async function encryptForConvo(convoId, plaintext){
    const key = await ensureConvoKey(convoId);
    if(!key) throw new Error("Locked: re-login to unlock E2EE.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, enc.encode(plaintext));
    return {ciphertext: b64u(ct), nonce: b64u(iv)};
  }

  async function decryptForConvo(convoId, ciphertextB64, nonceB64){
    const key = await getConvoKey(convoId);
    if(!key) return "[Encrypted — re-login to decrypt]";
    try{
      const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv: new Uint8Array(unb64u(nonceB64))}, key, unb64u(ciphertextB64));
      return dec.decode(pt);
    }catch{
      return "[Could not decrypt]";
    }
  }

  // ---------- rendering ----------
  function setTitle(){
    const c = cfg.convos.find(x=>x.id===currentId);
    document.getElementById("topTitle").textContent = c ? c.name : "Chat";
  }

  function renderMessageBlock(username, text, createdAt, attachmentId){
    const wrap = document.createElement("div");
    wrap.className = "msg";
    wrap.innerHTML = `
      <div class="avatar" aria-hidden="true"></div>
      <div class="bubblewrap">
        <div class="meta">
          <div class="name"></div>
          <div class="time"></div>
        </div>
        <div class="text"></div>
      </div>`;
    wrap.querySelector(".name").textContent = username;
    wrap.querySelector(".time").textContent = new Date(createdAt).toLocaleString();
    wrap.querySelector(".text").textContent = text;
    if(attachmentId){
      const a = document.createElement("div");
      a.className = "filelink";
      a.innerHTML = `<a href="/files/${attachmentId}">Download file</a>`;
      wrap.querySelector(".bubblewrap").appendChild(a);
    }
    $messages.appendChild(wrap);
  }

  async function loadHistory(){
    if(!currentId) return;
    const r = await fetch(`/api/conversations/${encodeURIComponent(currentId)}/messages`);
    const msgs = await r.json();
    $messages.innerHTML = "";
    for(const m of msgs){
      const text = await decryptForConvo(currentId, m.ciphertext, m.nonce);
      renderMessageBlock(m.username, text, m.created_at, m.attachment_id);
    }
    $messages.scrollTop = $messages.scrollHeight;
  }

  async function loadMembers(){
    if(!currentId) return;
    const r = await fetch(`/api/conversations/${encodeURIComponent(currentId)}/members`);
    const j = await r.json();
    currentMeta = j;

    const isGroup = j.type === "group";
    $membersPanel.style.display = isGroup ? "flex" : "none";

    if(!isGroup) return;

    $membersList.innerHTML = "";
    for(const m of j.members){
      const el = document.createElement("div");
      el.className = "member";
      el.dataset.uid = m.id;
      el.dataset.username = m.username;
      el.dataset.isFriend = m.is_friend ? "1" : "0";
      el.dataset.isSelf = m.is_self ? "1" : "0";
      el.dataset.isOwner = m.is_owner ? "1" : "0";
      el.innerHTML = `
        <div class="memberDot"></div>
        <div class="memberName"></div>
        <div class="badge"></div>
      `;
      el.querySelector(".memberName").textContent = m.username;
      el.querySelector(".badge").textContent = m.is_owner ? "Owner" : (m.is_self ? "You" : "");
      $membersList.appendChild(el);
    }
  }

  // ---------- actions ----------
  async function sendText(){
    const text = ($text.value || "").trim();
    if(!text || !currentId) return;
    const {ciphertext, nonce} = await encryptForConvo(currentId, text);
    socket.emit("message_send", {conversationId: currentId, ciphertext, nonce});
    $text.value="";
  }

  async function sendFile(){
    if(!currentId) return;
    const f = $file.files && $file.files[0];
    if(!f) return;

    const key = await ensureConvoKey(currentId);
    if(!key) throw new Error("Locked: re-login to unlock E2EE.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const bytes = new Uint8Array(await f.arrayBuffer());
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, bytes);

    const blob = new Blob([ct], {type:"application/octet-stream"});
    const fd = new FormData();
    fd.append("conversation_id", currentId);
    fd.append("mime", "application/octet-stream");
    fd.append("file", blob, f.name + ".enc");

    const res = await fetch("/upload", {method:"POST", body: fd}).then(r=>r.json());
    const metaText = `[File: ${f.name}]`;
    const msg = await encryptForConvo(currentId, metaText);
    socket.emit("message_send", {conversationId: currentId, ciphertext: msg.ciphertext, nonce: msg.nonce, attachment_id: res.file_id});

    $file.value="";
    $fileChip.textContent="No file selected";
  }

  // ---------- sockets ----------
  function setupSockets(){
    socket = io();
    socket.on("connect", ()=> $conn.textContent="Connected");
    socket.on("disconnect", ()=> $conn.textContent="Disconnected");
    socket.on("connected", ()=> { if(currentId) socket.emit("convo_join", {conversationId: currentId}); });

    socket.on("message_new", async (m)=>{
      if(!m || m.conversationId !== currentId) return;
      const text = await decryptForConvo(currentId, m.ciphertext, m.nonce);
      renderMessageBlock(m.user.username, text, m.createdAt, m.attachment_id);
      $messages.scrollTop = $messages.scrollHeight;
    });

    // realtime reload/refresh
    socket.on("friend_request", ()=> location.reload());
    socket.on("friend_accept", ()=> location.reload());
    socket.on("friend_remove", ()=> location.reload());
    socket.on("group_joined", ()=> location.reload());
    socket.on("group_kicked", ()=> location.reload());

    socket.on("group_left", (e)=>{
      if(e && e.conversation_id === currentId){
        location.reload();
      }else{
        loadMembers().catch(()=>{});
      }
    });
    socket.on("group_member_join", (e)=>{
      if(e && e.conversation_id === currentId) loadMembers().catch(()=>{});
    });
  }

  // ---------- context menus ----------
  function friendMenu(fid, username, x, y){
    showCtx(x,y,[
      {label:"Message", onClick: async ()=>{
        await formPost("/dm/start", {friend_id: fid});
        location.reload();
      }},
      {type:"sep"},
      {label:"Remove friend", danger:true, onClick: async ()=>{
        await formPost("/friends/remove", {friend_id: fid});
        location.reload();
      }}
    ]);
  }

  function memberMenu(uid, username, isFriend, x, y){
    const items = [];
    if(isFriend){
      items.push({label:"Remove friend", danger:true, onClick: async ()=>{
        await formPost("/friends/remove", {friend_id: uid});
        location.reload();
      }});
    }
    if(currentMeta && currentMeta.type==="group"){
      const amOwner = currentMeta.owner_id === cfg.user_id;
      if(amOwner && uid !== cfg.user_id){
        items.push({label:"Kick from group", danger:true, onClick: async ()=>{
          await formPost("/groups/kick", {conversation_id: currentId, user_id: uid});
          await loadMembers();
        }});
      }
    }
    if(items.length===0){
      items.push({label:"No actions available", onClick: async ()=>{}});
    }
    showCtx(x,y,items);
  }

  // ---------- UI wiring ----------
  function wireUi(){
    document.addEventListener("click", (e)=>{
      if(!$ctx.hidden && !e.target.closest(".ctxMenu")) hideCtx();
    });
    document.addEventListener("keydown", (e)=>{
      if(e.key==="Escape") hideCtx();
    });

    $chatList.addEventListener("click", async (e)=>{
      const btn = e.target.closest("button.chatPill");
      if(!btn) return;
      currentId = btn.dataset.cid;
      setTitle();
      hideCtx();
      await loadHistory();
      await loadMembers();
      socket.emit("convo_join", {conversationId: currentId});
    });

    $send.addEventListener("click", ()=> sendText().catch(err=>alert(err.message)));
    $text.addEventListener("keydown", (e)=>{
      if(e.key==="Enter" && !e.shiftKey){
        e.preventDefault();
        sendText().catch(err=>alert(err.message));
      }
    });

    $attachBtn.addEventListener("click", ()=> $file.click());
    $file.addEventListener("change", ()=>{
      const f = $file.files && $file.files[0];
      $fileChip.textContent = f ? f.name : "No file selected";
      if(f) sendFile().catch(err=>alert(err.message));
    });

    // Top actions keep your existing prompts (simple)
    $inviteBtn.addEventListener("click", ()=>{
      const usernames = prompt("Invite which friends? (comma-separated usernames)");
      if(!usernames) return;
      (async ()=>{
        const names = usernames.split(",").map(s=>s.trim()).filter(Boolean);
        const ids=[];
        for(const n of names){
          const j = await fetch(`/api/users/by-username?q=${encodeURIComponent(n)}`).then(r=>r.json());
          if(j.user) ids.push(j.user.id);
        }
        await formPost("/groups/invite", {conversation_id: currentId, member_ids: ids.join(",")});
        await loadMembers();
      })();
    });

    $leaveBtn.addEventListener("click", ()=>{
      if(!confirm("Leave this group?")) return;
      formPost("/groups/leave", {conversation_id: currentId}).then(()=>location.reload());
    });

    $kickBtn.addEventListener("click", ()=>{
      const uname = prompt("Kick which username?");
      if(!uname) return;
      (async ()=>{
        const j = await fetch(`/api/users/by-username?q=${encodeURIComponent(uname)}`).then(r=>r.json());
        if(!j.user) return alert("User not found");
        await formPost("/groups/kick", {conversation_id: currentId, user_id: j.user.id});
        await loadMembers();
      })();
    });

    // Friend list: click = start DM, right-click = context menu
    $friendsList.addEventListener("click", async (e)=>{
      const it = e.target.closest(".friendItem");
      if(!it) return;
      await formPost("/dm/start", {friend_id: it.dataset.fid});
      location.reload();
    });
    $friendsList.addEventListener("contextmenu", (e)=>{
      const it = e.target.closest(".friendItem");
      if(!it) return;
      e.preventDefault();
      friendMenu(it.dataset.fid, it.dataset.username, e.clientX, e.clientY);
    });

    // Members list: right click menu
    $membersList.addEventListener("contextmenu", (e)=>{
      const it = e.target.closest(".member");
      if(!it) return;
      e.preventDefault();
      if(it.dataset.isSelf==="1") return; // no self menu
      memberMenu(it.dataset.uid, it.dataset.username, it.dataset.isFriend==="1", e.clientX, e.clientY);
    });

    // Create group: translate usernames -> ids before submit (same as earlier)
    const groupFriends = document.getElementById("groupFriends");
    const groupMemberIds = document.getElementById("groupMemberIds");
    document.getElementById("groupCreate").addEventListener("submit", async (e)=>{
      e.preventDefault();
      const names = (groupFriends.value||"").split(",").map(s=>s.trim()).filter(Boolean);
      const ids=[];
      for(const n of names){
        const j = await fetch(`/api/users/by-username?q=${encodeURIComponent(n)}`).then(r=>r.json());
        if(j.user) ids.push(j.user.id);
      }
      groupMemberIds.value = ids.join(",");
      e.target.submit();
    });
  }

  async function init(){
    // Ensure crypto identity exists (for future upgrades) + keep your existing E2EE flow
    try{ await loadOrCreateIdentity(); }catch{}
    setTitle();
    setupSockets();
    wireUi();
    await loadHistory();
    await loadMembers();
    if(currentId) socket.emit("convo_join", {conversationId: currentId});
  }

  init();
})();