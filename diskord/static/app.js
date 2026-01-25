(function () {
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

  function addMsg(username, content, createdAt){
    const wrap = document.createElement("div");
    wrap.className = "msg";
    const t = new Date(createdAt).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
    let extra = "";
    if (arguments.length > 3) {
      const file = arguments[3];
      if (file && file.url) extra = `<div class="small"><a href="${esc(file.url)}">Download: ${esc(file.name || "file")}</a></div>`;
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
  if($modal) $modal.addEventListener("click", e=>{ if(e.target===$modal) closeModal(); });

  scrollToBottom();
})();
