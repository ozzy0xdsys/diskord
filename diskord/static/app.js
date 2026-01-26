(f

  if($newAnnBtn){
    $newAnnBtn.addEventListener("click", ()=>{
      if($modalTitle) $modalTitle.textContent = "New announcement";
      if($groupForm) $groupForm.style.display = "none";
      if($annForm) $annForm.style.display = "block";
      $modal.hidden = false;
    });
  }
unction () {
  const cfg = window.PYCORD;
  const $messages = document.getElementById("messages");
  const $text = document.getElementById("text");
  const $file = document.getElementById("file");
  const $fileChip = document.getElementById("fileChip");
  const $attachBtn = document.getElementById("attachBtn");
  const $send = document.getElementById("send");
  const $conn = document.getElementById("connState");
  const $topTitle = document.getElementById("topTitle");
  const $chatList = document.getElementById("chatList");

  let currentId = cfg.selectedId;

  function scrollToBottom(){ $messages.scrollTop = $messages.scrollHeight; }
  function isNearBottom(){
    const pad = 120;
    return ($messages.scrollHeight - $messages.scrollTop - $messages.clientHeight) < pad;
  }
  function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  function addMsg(msg){
    const username = msg.username;
    const content = msg.content;
    const createdAt = msg.created_at || msg.createdAt;
    const avatarUrl = msg.avatar_url || (msg.user && msg.user.avatar_url) || null;
    const file = msg.file || (msg.attachment ? msg.attachment : null);

    const near = isNearBottom();
    const last = $messages.lastElementChild;
    const canGroup = last && last.classList.contains("msg") && last.getAttribute("data-user") === username;

    let body;
    if(canGroup){
      body = last.querySelector(".body");
    }else{
      const wrap = document.createElement("div");
      wrap.className = "msg";
      wrap.setAttribute("data-user", username);
      const t = new Date(createdAt).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
      const avatar = avatarUrl ? `<img src="${esc(avatarUrl)}" alt=""/>` : `<span>${esc(username[0].toUpperCase())}</span>`;
      wrap.innerHTML = `<div class="meta"><div class="avatar">${avatar}</div><b>${esc(username)}</b> · ${esc(t)}</div>`;
      body = document.createElement("div");
      body.className = "body";
      wrap.appendChild(body);
      $messages.appendChild(wrap);
    }

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = content;
    body.appendChild(bubble);

    // attachment (optional)
    if(msg.has_attachment){
      const a = document.createElement("div");
      a.className = "small";
      a.innerHTML = `<a href="/files/${esc(msg.id)}">Download: ${esc(msg.attachment_name || "file")}</a>`;
      body.appendChild(a);
    }else if(file && file.url){
      const a = document.createElement("div");
      a.className = "small";
      a.innerHTML = `<a href="${esc(file.url)}">Download: ${esc(file.name || "file")}</a>`;
      body.appendChild(a);
    }

    if(near) scrollToBottom();
  }

    wrap.innerHTML = `<div class="meta"><b>${esc(username)}</b> · ${esc(t)}</div><div>${esc(content)}</div>${extra}`;
    const near = isNearBottom();
    $messages.appendChild(wrap);
    if(near) scrollToBottom();
  }


  function updateFileChip(){
    const file = ($file && $file.files && $file.files[0]) ? $file.files[0] : null;
    if(!$fileChip) return;
    if(!file){
      $fileChip.hidden = true;
      $fileChip.textContent = "";
      return;
    }
    $fileChip.hidden = false;
    const mb = (file.size / (1024*1024)).toFixed(2);
    $fileChip.textContent = `${file.name} (${mb} MB) — click to remove`;
  }

  if($file){
    $file.addEventListener("change", updateFileChip);
  }
  if($fileChip){
    $fileChip.addEventListener("click", ()=>{
      if($file) $file.value = "";
      updateFileChip();
      if($text) $text.focus();
    });
  }

  async function loadMessages(conversationId){
    const res = await fetch(`/api/conversations/${conversationId}/messages`, { credentials: "same-origin" });
    if(!res.ok) return;
    const msgs = await res.json();
    $messages.innerHTML = "";
    for(const m of msgs){
      addMsg(m.username, m.content, m.created_at, (m.has_attachment ? {url:`/files/${m.id}`, name:m.attachment_name} : null));
    }
  }

  const socket = io({ auth: { session: cfg.session } });

  socket.on("connect", ()=>{
    $conn.textContent = "Online";
    if(currentId) socket.emit("convo_join", { conversationId: currentId });
    scrollToBottom();
  });
  socket.on("disconnect", ()=> $conn.textContent = "Offline");
  socket.on("connect_error", ()=> $conn.textContent = "Auth error");

  socket.on("message_new", (p)=>{
    if(p.conversationId !== currentId) return;
    addMsg(p.user.username, p.content, p.createdAt, (p.has_attachment ? {url: (p.file_url || `/files/${p.id}`), name: p.attachment_name} : null));
  });

  async function send(){
    if(!currentId) return;
    const file = ($file && $file.files && $file.files[0]) ? $file.files[0] : null;
    const content = ($text.value||"").trim();

    if(file){
      // upload via HTTP (10MB max enforced server-side)
      const fd = new FormData();
      fd.append("conversation_id", currentId);
      fd.append("csrf", cfg.csrf);
      fd.append("file", file);

      const res = await fetch("/upload", { method:"POST", body: fd, credentials:"same-origin" });
      if(!res.ok){
        alert(await res.text());
        return;
      }
      if($file) $file.value = "";
      if($fileChip){ $fileChip.hidden = true; $fileChip.textContent=""; }
      $text.value = "";
      $text.focus();
      return;
    }

    if(!content) return;
    socket.emit("message_send", { conversationId: currentId, content });
    $text.value = "";
    $text.focus();
  }
  if($send) $send.addEventListener("click", ()=>send());
  if($text) $text.addEventListener("keydown", e=>{ if(e.key==="Enter") send(); });

  if($chatList){
    $chatList.addEventListener("click", async (e)=>{
      const btn = e.target.closest(".item");
      if(!btn) return;
      const cid = btn.getAttribute("data-cid");
      if(!cid || cid === currentId) return;
      document.querySelectorAll(".item.active").forEach(x=>x.classList.remove("active"));
      btn.classList.add("active");
      currentId = cid;
      $topTitle.textContent = btn.textContent.trim();
      $text.disabled = false; $send.disabled = false;
      socket.emit("convo_join", { conversationId: currentId });
      await loadMessages(currentId);
    });
  }

  // Group modal
  const $modal = document.getElementById("modal");
  const $newGroupBtn = document.getElementById("newGroupBtn");
  const $newAnnBtn = document.getElementById("newAnnBtn");
  const $modalTitle = document.getElementById("modalTitle");
  const $annForm = document.getElementById("annCreateForm");
  const $annIds = document.getElementById("ann_member_ids");
  const $groupForm = document.getElementById("groupCreateForm");

  const $closeModal = document.getElementById("closeModal");
  const $friendPicks = document.getElementById("friendPicks");
  const $memberIds = document.getElementById("member_ids");
  let selected = new Set();

  function renderPicks(){
    $friendPicks.innerHTML = "";
    const friends = cfg.friends || [];
    if(friends.length === 0){
      $friendPicks.innerHTML = `<div class="small">No friends yet.</div>`;
      return;
    }
    for(const f of friends){
      const row = document.createElement("div");
      row.className = "pick " + (selected.has(f.id) ? "on" : "");
      row.innerHTML = `<span>${esc(f.username)}</span><span>${selected.has(f.id) ? "✓" : "+"}</span>`;
      row.addEventListener("click", ()=>{
        if(selected.has(f.id)) selected.delete(f.id);
        else selected.add(f.id);
        $memberIds.value = Array.from(selected).join(",");
        renderPicks();
      });
      $friendPicks.appendChild(row);
    }
    $memberIds.value = Array.from(selected).join(",");
  }

  function openModal(){ selected = new Set(); renderPicks(); $modal.classList.remove("hidden"); }
  function closeModal(){ $modal.classList.add("hidden"); }
  if($newGroupBtn) $newGroupBtn.addEventListener("click", openModal);
  if($closeModal) $closeModal.addEventListener("click", closeModal);
  if($modal) $modal.addEventListener("click", e=>{ if(e.target===$modal) closeModal(); 

  const $callBtn = document.getElementById("callBtn");
  let pc = null;
  let localStream = null;
  let callConvoId = null;
  let inCall = false;

  function isDmConversation(convoId){
    const c = (window.PYCORD.convos || []).find(x => x.id === convoId);
    return c && c.type === "dm";
  }

  async function startLocalAudio(){
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video:false});
  }

  function teardownCall(){
    inCall = false;
    if(pc){ pc.close(); pc = null; }
    if(localStream){
      for(const t of localStream.getTracks()) t.stop();
      localStream = null;
    }
    if($callBtn) $callBtn.textContent = "🎙️ Call";
  }

  async function ensurePeer(){
    pc = new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
    pc.onicecandidate = (e)=>{
      if(e.candidate && callConvoId){
        socket.emit("call_ice",{conversationId:callConvoId,candidate:e.candidate});
      }
    };
    pc.ontrack = (e)=>{
      // play remote audio
      let audio = document.getElementById("remoteAudio");
      if(!audio){
        audio = document.createElement("audio");
        audio.id = "remoteAudio";
        audio.autoplay = true;
        document.body.appendChild(audio);
      }
      audio.srcObject = e.streams[0];
    };
    for(const track of localStream.getTracks()){
      pc.addTrack(track, localStream);
    }
  }

  async function placeCall(){
    if(!currentId) return;
    if(!isDmConversation(currentId)) return;
    callConvoId = currentId;
    await startLocalAudio();
    await ensurePeer();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit("call_offer",{conversationId:callConvoId,sdp:offer});
    inCall = true;
    if($callBtn) $callBtn.textContent = "🔴 Hang up";
  }

  async function acceptCall(conversationId, offer){
    callConvoId = conversationId;
    await startLocalAudio();
    await ensurePeer();
    await pc.setRemoteDescription(offer);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit("call_answer",{conversationId:callConvoId,sdp:answer});
    inCall = true;
    if($callBtn) $callBtn.textContent = "🔴 Hang up";
  }

  if($callBtn){
    $callBtn.addEventListener("click", async ()=>{
      try{
        if(inCall){
          socket.emit("call_hangup",{conversationId:callConvoId});
          teardownCall();
          return;
        }
        await placeCall();
      }catch(e){
        console.error(e);
        teardownCall();
        alert("Could not start call (mic permission?)");
      }
    });
  }

  socket.on("call_offer", async (p)=>{
    try{
      if(!p || !p.conversationId || !p.sdp) return;
      if(p.conversationId !== currentId) return; // only if you're in that DM
      if(inCall) return;
      const ok = confirm(`Incoming call from ${p.from?.username || "friend"}. Accept?`);
      if(!ok) return;
      await acceptCall(p.conversationId, p.sdp);
    }catch(e){
      console.error(e);
      teardownCall();
    }
  });

  socket.on("call_answer", async (p)=>{
    try{
      if(!pc || !p || p.conversationId !== callConvoId) return;
      await pc.setRemoteDescription(p.sdp);
    }catch(e){
      console.error(e);
      teardownCall();
    }
  });

  socket.on("call_ice", async (p)=>{
    try{
      if(!pc || !p || p.conversationId !== callConvoId) return;
      await pc.addIceCandidate(p.candidate);
    }catch(e){
      // ignore
    }
  });

  socket.on("call_hangup", (p)=>{
    if(p && p.conversationId === callConvoId){
      teardownCall();
      alert("Call ended.");
    }
  });

});

  scrollToBottom();
})();
