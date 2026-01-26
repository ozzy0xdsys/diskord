(() => {
  const cfg = window.PYCORD || {};
  const $messages = document.getElementById("messages");
  const $text = document.getElementById("text");
  const $file = document.getElementById("file");
  const $fileChip = document.getElementById("fileChip");
  const $attachBtn = document.getElementById("attachBtn");
  const $send = document.getElementById("send");
  const $conn = document.getElementById("connState");
  const $topTitle = document.getElementById("topTitle");
  const $chatList = document.getElementById("chatList");

  const $modal = document.getElementById("modal");
  const $modalTitle = document.getElementById("modalTitle");
  const $groupForm = document.getElementById("groupCreateForm");
  const $annForm = document.getElementById("annCreateForm");
  const $inviteForm = document.getElementById("inviteForm");
  const $annIds = document.getElementById("ann_member_ids");
  const $inviteIds = document.getElementById("invite_member_ids");
  const $inviteConvoId = document.getElementById("invite_conversation_id");

  const $newGroupBtn = document.getElementById("newGroupBtn");
  const $newAnnBtn = document.getElementById("newAnnBtn");
  const $inviteBtn = document.getElementById("inviteBtn");
  const $callBtn = document.getElementById("callBtn");

  let currentId = cfg.selectedId || null;
  let socket = null;

  function esc(s){ return (s ?? "").toString().replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  function scrollToBottom(){
    $messages.scrollTop = $messages.scrollHeight;
  }

  function isNearBottom(){
    const gap = $messages.scrollHeight - ($messages.scrollTop + $messages.clientHeight);
    return gap < 120;
  }

  function convoById(id){
    return (cfg.convos || []).find(c => c.id === id) || null;
  }

  function setTopTitle(){
    const c = convoById(currentId);
    $topTitle.textContent = c ? c.name : "Select a chat";
    // Toggle buttons
    if($callBtn) $callBtn.style.display = (c && c.type === "dm") ? "inline-flex" : "none";
    if($inviteBtn) $inviteBtn.style.display = (c && (c.type === "group" || c.type === "announcement")) ? "inline-flex" : "none";
  }

  function setActiveButton(){
    if(!$chatList) return;
    [...$chatList.querySelectorAll("button.item")].forEach(b=>{
      b.classList.toggle("active", b.dataset.cid === currentId);
    });
  }

  async function loadMessages(){
    if(!currentId) return;
    const r = await fetch(`/api/conversations/${encodeURIComponent(currentId)}/messages`);
    const msgs = await r.json();
    renderMessages(msgs);
  }

  function renderMessages(msgs){
    $messages.innerHTML = "";
    let lastUser = null;
    let lastBody = null;
    for(const m of msgs){
      const same = lastUser && lastUser === m.username && lastBody;
      if(!same){
        const wrap = document.createElement("div");
        wrap.className = "msg";
        wrap.setAttribute("data-user", m.username);

        const t = new Date(m.created_at).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
        const avatar = m.avatar_url ? `<img src="${esc(m.avatar_url)}" alt=""/>` : `<span>${esc(m.username[0].toUpperCase())}</span>`;

        wrap.innerHTML = `
          <div class="meta">
            <div class="avatar">${avatar}</div>
            <div class="meta-text">
              <b>${esc(m.username)}</b>
              <span class="dot">•</span>
              <span class="time">${esc(t)}</span>
            </div>
          </div>
        `;

        const body = document.createElement("div");
        body.className = "body";
        wrap.appendChild(body);
        $messages.appendChild(wrap);

        lastUser = m.username;
        lastBody = body;
      }

      const bubble = document.createElement("div");
      bubble.className = "bubble";
      bubble.textContent = m.content;
      lastBody.appendChild(bubble);

      if(m.has_attachment){
        const a = document.createElement("a");
        a.className = "filelink";
        a.href = `/files/${encodeURIComponent(m.id)}`;
        a.textContent = `Download: ${m.attachment_name || "file"}`;
        lastBody.appendChild(a);
      }
    }
    scrollToBottom();
  }

  function appendIncoming(m){
    const near = isNearBottom();
    const last = $messages.lastElementChild;
    const canGroup = last && last.classList.contains("msg") && last.getAttribute("data-user") === m.username;
    let body;

    if(canGroup){
      body = last.querySelector(".body");
    }else{
      const wrap = document.createElement("div");
      wrap.className = "msg";
      wrap.setAttribute("data-user", m.username);

      const t = new Date(m.created_at || m.createdAt).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
      const avatar = (m.avatar_url || (m.user && m.user.avatar_url)) ? `<img src="${esc(m.avatar_url || m.user.avatar_url)}" alt=""/>` : `<span>${esc(m.username[0].toUpperCase())}</span>`;

      wrap.innerHTML = `
        <div class="meta">
          <div class="avatar">${avatar}</div>
          <div class="meta-text">
            <b>${esc(m.username)}</b>
            <span class="dot">•</span>
            <span class="time">${esc(t)}</span>
          </div>
        </div>
      `;
      body = document.createElement("div");
      body.className = "body";
      wrap.appendChild(body);
      $messages.appendChild(wrap);
    }

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = m.content;
    body.appendChild(bubble);

    if(m.has_attachment){
      const a = document.createElement("a");
      a.className = "filelink";
      a.href = `/files/${encodeURIComponent(m.id)}`;
      a.textContent = `Download: ${m.attachment_name || "file"}`;
      body.appendChild(a);
    }
    if(near) scrollToBottom();
  }

  async function sendText(){
    if(!currentId) return;
    const text = ($text.value || "").trim();
    if(!text) return;
    socket.emit("message_send", { conversationId: currentId, content: text });
    $text.value = "";
  }

  async function sendFile(){
    if(!currentId) return;
    const f = $file.files && $file.files[0];
    if(!f) return;
    const fd = new FormData();
    fd.append("csrf", cfg.csrf);
    fd.append("conversation_id", currentId);
    fd.append("file", f);
    const r = await fetch("/upload", { method:"POST", body: fd });
    if(!r.ok){
      alert("Upload failed");
      return;
    }
    $file.value = "";
    $fileChip.textContent = "No file selected";
  }

  function setupSocket(){
    socket = io({ auth: { session: cfg.session } });

    socket.on("connect", ()=>{ $conn.textContent = "Connected"; });
    socket.on("disconnect", ()=>{ $conn.textContent = "Disconnected"; });
    socket.on("connect_error", ()=>{ $conn.textContent = "Auth error"; });

    socket.on("connected", ()=>{ if(currentId) socket.emit("convo_join", {conversationId: currentId}); });

    socket.on("message_new", (m)=>{
      // server sends {id, content, createdAt, user:{username, avatar_url}, conversationId}
      if(!m || m.conversationId !== currentId) return;
      appendIncoming({
        id: m.id,
        username: m.user.username,
        avatar_url: m.user.avatar_url || null,
        content: m.content,
        created_at: m.createdAt,
        has_attachment: false
      });
    });
  }

  function openModal(mode){
    if(!$modal) return;
    $modal.hidden = false;
    if($modalTitle){
      $modalTitle.textContent = mode === "announcement" ? "New announcement" :
                                mode === "invite" ? "Invite friends" :
                                "New group";
    }
    if($groupForm) $groupForm.style.display = (mode === "group") ? "block" : "none";
    if($annForm) $annForm.style.display = (mode === "announcement") ? "block" : "none";
    if($inviteForm) $inviteForm.style.display = (mode === "invite") ? "block" : "none";
    if(mode === "invite" && $inviteConvoId) $inviteConvoId.value = currentId || "";
  }

  function closeModal(){
    if($modal) $modal.hidden = true;
  }

  // === Voice calling (DM only) ===
  let pc = null;
  let localStream = null;
  let callConvoId = null;
  let inCall = false;

  function teardownCall(silent){
    inCall = false;
    if(pc){ pc.close(); pc = null; }
    if(localStream){
      for(const t of localStream.getTracks()) t.stop();
      localStream = null;
    }
    callConvoId = null;
    if($callBtn) $callBtn.textContent = "🎙️ Call";
    if(!silent) {}
  }

  async function startLocalAudio(){
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video:false});
  }

  async function ensurePeer(){
    pc = new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
    pc.onicecandidate = (e)=>{
      if(e.candidate && callConvoId){
        socket.emit("call_ice",{conversationId:callConvoId,candidate:e.candidate});
      }
    };
    pc.ontrack = (e)=>{
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
    const c = convoById(currentId);
    if(!c || c.type !== "dm") return;
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

  function wireCallEvents(){
    if(!$callBtn) return;
    $callBtn.addEventListener("click", async ()=>{
      try{
        if(inCall){
          socket.emit("call_hangup",{conversationId: callConvoId});
          teardownCall(true);
          return;
        }
        await placeCall();
      }catch(e){
        console.error(e);
        teardownCall(true);
        alert("Could not start call (mic permission?)");
      }
    });

    socket.on("call_offer", async (p)=>{
      try{
        if(!p || !p.conversationId || !p.sdp) return;
        if(p.conversationId !== currentId) return;
        if(inCall) return;
        const ok = confirm(`Incoming call from ${p.from?.username || "friend"}. Accept?`);
        if(!ok) return;
        await acceptCall(p.conversationId, p.sdp);
      }catch(e){
        console.error(e);
        teardownCall(true);
      }
    });

    socket.on("call_answer", async (p)=>{
      try{
        if(!pc || !p || p.conversationId !== callConvoId) return;
        await pc.setRemoteDescription(p.sdp);
      }catch(e){
        console.error(e);
        teardownCall(true);
      }
    });

    socket.on("call_ice", async (p)=>{
      try{
        if(!pc || !p || p.conversationId !== callConvoId) return;
        await pc.addIceCandidate(p.candidate);
      }catch(e){}
    });

    socket.on("call_hangup", (p)=>{
      if(p && p.conversationId === callConvoId){
        teardownCall(true);
        alert("Call ended.");
      }
    });
  }

  function wireUi(){
    // select conversation
    if($chatList){
      $chatList.addEventListener("click", async (e)=>{
        const btn = e.target.closest("button.item");
        if(!btn) return;
        currentId = btn.dataset.cid;
        setTopTitle();
        setActiveButton();
        await loadMessages();
        if(socket) socket.emit("convo_join", {conversationId: currentId});
      });
    }

    // send text
    $send.addEventListener("click", ()=> sendText());
    $text.addEventListener("keydown", (e)=>{
      if(e.key === "Enter" && !e.shiftKey){
        e.preventDefault();
        sendText();
      }
    });

    // file UI
    $attachBtn.addEventListener("click", ()=> $file.click());
    $file.addEventListener("change", ()=>{
      const f = $file.files && $file.files[0];
      $fileChip.textContent = f ? f.name : "No file selected";
    });

    // send file on form submit (upload button is same send? keep separate)
    document.getElementById("uploadForm")?.addEventListener("submit", (e)=>{
      e.preventDefault();
      sendFile();
    });

    // modal
    $newGroupBtn?.addEventListener("click", ()=> openModal("group"));
    $newAnnBtn?.addEventListener("click", ()=> openModal("announcement"));
    $inviteBtn?.addEventListener("click", ()=> openModal("invite"));

    document.getElementById("modalClose")?.addEventListener("click", closeModal);
    $modal?.addEventListener("click", (e)=>{ if(e.target === $modal) closeModal(); });
    document.addEventListener("keydown", (e)=>{ if(e.key === "Escape") closeModal(); });

    // ensure selected ids propagate to all forms
    const memberIdsInput = document.getElementById("member_ids");
    const checkList = document.getElementById("friendChecks");
    function syncSelected(){
      if(!checkList) return;
      const ids = [...checkList.querySelectorAll("input[type=checkbox]:checked")].map(x=>x.value);
      if(memberIdsInput) memberIdsInput.value = ids.join(",");
      if($annIds) $annIds.value = ids.join(",");
      if($inviteIds) $inviteIds.value = ids.join(",");
    }
    checkList?.addEventListener("change", syncSelected);
    syncSelected();
  }

  async function init(){
    setTopTitle();
    setActiveButton();
    setupSocket();
    wireUi();
    wireCallEvents();
    if(currentId){
      await loadMessages();
      socket.emit("convo_join", {conversationId: currentId});
    }
  }

  init();
})();