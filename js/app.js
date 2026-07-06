/* ============================================================================
   app.js — application state, business logic, rendering, and event handling.
   Loaded last, after config.js, utils.js, firebase.js, and crypto.js.
   ========================================================================= */

const root = $('#root');

// ---- in-memory session state (never persisted) ----
let session = {
  username: null,
  displayName: null,
  privateKey: null,   // CryptoKey, RSA-OAEP, decrypt-capable
  publicKeyJwk: null,
  fingerprint: null,
  retentionDays: DEFAULT_RETENTION_DAYS,
  privacy: { blurOnBlur: false, disableSelection: false, hideNotificationPreview: false },
};
let directory = [];          // [{username, displayName, publicKeyJwk, fingerprint}]
let convos = [];             // [{id, type, members, name, createdAt, _retentionMs}]
let activeConvoId = null;
let messagesCache = {};      // convoId -> decrypted message list
let notifiedIds = new Set(); // message ids we've already fired a browser notification for
let pollTimer = null;
let ui = { authTab: 'login', authErr: '', busy: false, authSteps: [], showNewChat: false, picked: [], showSettings: false, showSchedule: false };

// ------------------------------------------------------------- directory

async function loadDirectory(){
  directory = (await getJSON('directory', true)) || [];
}

// -------------------------------------------------------------- auth flow

async function signUp(username, displayName, password, onStep){
  username = username.trim().toLowerCase();
  displayName = displayName.trim() || username;
  if (!username || !password) throw new Error('Username and password are required.');
  if (password.length < 8) throw new Error('Use a password of at least 8 characters — it protects your private key.');

  onStep?.('checking username availability');
  await loadDirectory();
  if (directory.some(d => d.username === username)) throw new Error('That username is already sealed by someone else.');

  const existingAccount = await getJSON('account:'+username, true);
  if (existingAccount) throw new Error('That username is already taken.');

  onStep?.('generating RSA-2048 keypair');
  const keypair = await generateKeypair();
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);

  onStep?.('deriving key from passphrase (PBKDF2, 250000 rounds)');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapKey = await deriveWrapKey(password, salt);

  onStep?.('sealing private key with AES-256-GCM');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encPrivate = await crypto.subtle.encrypt({name:'AES-GCM', iv}, wrapKey, strToBuf(JSON.stringify(privateKeyJwk)));

  const account = {
    username, displayName,
    publicKeyJwk,
    salt: buf2b64(salt),
    iv: buf2b64(iv),
    encPrivateKey: buf2b64(encPrivate),
    createdAt: Date.now(),
    lastLoginAt: Date.now(),
    retentionDays: DEFAULT_RETENTION_DAYS,
    privacy: { blurOnBlur: false, disableSelection: false, hideNotificationPreview: false }
  };
  onStep?.('writing account record');
  await setJSON('account:'+username, account, true);

  onStep?.('computing key fingerprint');
  const fp = await fingerprintOf(publicKeyJwk);
  directory.push({ username, displayName, publicKeyJwk, fingerprint: fp });
  await setJSON('directory', directory, true);

  onStep?.('done');
  session = {
    username, displayName, privateKey: keypair.privateKey, publicKeyJwk, fingerprint: fp,
    retentionDays: account.retentionDays, privacy: account.privacy
  };
  await setJSON('userConvos:'+username, [], true); // shared store, so this account's conversation list is discoverable next login
}

async function logIn(username, password){
  username = username.trim().toLowerCase();
  const account = await getJSON('account:'+username, true);
  if (!account) throw new Error('No account with that username.');

  const wrapKey = await deriveWrapKey(password, new Uint8Array(b642buf(account.salt)));
  let privateKeyJwk;
  try{
    const plain = await crypto.subtle.decrypt(
      {name:'AES-GCM', iv: new Uint8Array(b642buf(account.iv))}, wrapKey, b642buf(account.encPrivateKey)
    );
    privateKeyJwk = JSON.parse(bufToStr(plain));
  }catch(e){
    throw new Error('Wrong password.'); // AES-GCM auth tag fails to verify -> this IS the auth check
  }
  const privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['decrypt']);
  const fp = await fingerprintOf(account.publicKeyJwk);

  // Refresh lastLoginAt so this account doesn't get swept up by account expiry.
  // Older accounts (created before this feature existed) get sensible defaults here.
  account.lastLoginAt = Date.now();
  account.retentionDays = account.retentionDays || DEFAULT_RETENTION_DAYS;
  account.privacy = account.privacy || { blurOnBlur: false, disableSelection: false, hideNotificationPreview: false };
  await setJSON('account:'+username, account, true);

  session = {
    username, displayName: account.displayName, privateKey, publicKeyJwk: account.publicKeyJwk, fingerprint: fp,
    retentionDays: account.retentionDays, privacy: account.privacy
  };
}

// Best-effort cleanup: removes accounts that haven't logged in for
// ACCOUNT_EXPIRY_DAYS. There's no real server here, so this only runs when
// SOME logged-in user's browser happens to execute it (right after login) —
// it's not a guaranteed-timing job. Shared conversation history is
// deliberately left alone so the other side of a DM keeps their messages.
async function runAccountExpirySweep(){
  try{
    await loadDirectory();
    const now = Date.now();
    let changed = false;
    const survivors = [];
    for (const entry of directory){
      if (entry.username === session.username){ survivors.push(entry); continue; }
      const acc = await getJSON('account:'+entry.username, true);
      if (!acc){ changed = true; continue; } // already gone somehow -> drop stale directory entry
      const lastActive = acc.lastLoginAt || acc.createdAt || 0;
      if (now - lastActive > ACCOUNT_EXPIRY_MS){
        await setJSON('account:'+entry.username, null, true);      // PUT null deletes the path in Firebase
        await setJSON('userConvos:'+entry.username, null, true);
        changed = true;
      } else {
        survivors.push(entry);
      }
    }
    if (changed){ directory = survivors; await setJSON('directory', directory, true); }
  }catch(e){ /* best-effort only; a network hiccup here just means we try again next login */ }
}

function logOut(){
  session = { username:null, displayName:null, privateKey:null, publicKeyJwk:null, fingerprint:null, retentionDays: DEFAULT_RETENTION_DAYS, privacy: { blurOnBlur:false, disableSelection:false, hideNotificationPreview:false } };
  convos = []; messagesCache = {}; activeConvoId = null; notifiedIds = new Set();
  if (pollTimer) clearInterval(pollTimer);
  render();
}

// ---------------------------------------------------------- conversations

// Retention applies per-conversation as the SHORTEST setting among all its
// members — nobody's stricter preference gets silently overridden by
// someone else's looser one. Computed once when a conversation is opened
// and cached on the convo object, rather than re-fetched on every poll tick.
async function computeEffectiveRetentionMs(convo){
  let minDays = DEFAULT_RETENTION_DAYS;
  for (const uname of convo.members){
    if (uname === session.username){
      minDays = Math.min(minDays, session.retentionDays || DEFAULT_RETENTION_DAYS);
      continue;
    }
    const acc = await getJSON('account:'+uname, true);
    const days = (acc && acc.retentionDays) ? acc.retentionDays : DEFAULT_RETENTION_DAYS;
    minDays = Math.min(minDays, days);
  }
  convo._retentionMs = minDays * 24 * 60 * 60 * 1000;
  convo._retentionDays = minDays;
}

async function loadConvos(){
  const ids = (await getJSON('userConvos:'+session.username, true)) || [];
  const list = [];
  for (const id of ids){
    const c = await getJSON('convo:'+id, true);
    if (c) list.push(c);
  }
  list.sort((a,b)=> (b.lastActivity||b.createdAt) - (a.lastActivity||a.createdAt));
  // preserve any already-computed retention cache across reloads (poll ticks call loadConvos often)
  for (const c of list){
    const prev = convos.find(p=>p.id===c.id);
    if (prev && prev._retentionMs){ c._retentionMs = prev._retentionMs; c._retentionDays = prev._retentionDays; }
  }
  convos = list;
}

async function addConvoToUser(username, convoId){
  const list = (await getJSON('userConvos:'+username, true)) || [];
  if (!list.includes(convoId)){
    list.push(convoId);
    await setJSON('userConvos:'+username, list, true);
  }
}

function dmId(a,b){ return 'dm_' + [a,b].sort().join('__'); }

async function openOrCreateDM(otherUsername){
  const id = dmId(session.username, otherUsername);
  let c = await getJSON('convo:'+id, true);
  if (!c){
    c = { id, type:'dm', members:[session.username, otherUsername], createdAt: Date.now(), lastActivity: Date.now() };
    await setJSON('convo:'+id, c, true);
    await setJSON('messages:'+id, [], true);
    await addConvoToUser(session.username, id);
    await addConvoToUser(otherUsername, id);
  }
  await loadConvos();
  activeConvoId = id;
  const active = convos.find(x=>x.id===id);
  if (active) await computeEffectiveRetentionMs(active);
  await loadMessages(id);
  render();
}

async function createGroup(name, memberUsernames){
  const id = 'grp_' + randomId();
  const members = Array.from(new Set([session.username, ...memberUsernames]));
  const c = { id, type:'group', name: name || 'Untitled group', members, createdAt: Date.now(), lastActivity: Date.now() };
  await setJSON('convo:'+id, c, true);
  await setJSON('messages:'+id, [], true);
  for (const m of members) await addConvoToUser(m, id);
  await loadConvos();
  activeConvoId = id;
  const active = convos.find(x=>x.id===id);
  if (active) await computeEffectiveRetentionMs(active);
  await loadMessages(id);
  render();
}

// --------------------------------------------------------------- messages

async function loadMessages(convoId){
  let list = (await getJSON('messages:'+convoId, true)) || [];
  const now = Date.now();
  let changed = false;

  // Release any scheduled messages whose time has arrived. This also covers
  // "missed schedules" — if nobody's browser was open at the exact moment,
  // whoever opens this conversation next (sender or recipient) releases it.
  for (const m of list){
    if (m.status === 'scheduled' && m.scheduledFor && m.scheduledFor <= now){
      m.status = 'sent';
      changed = true;
    }
  }

  const beforeLen = list.length;
  list = list.filter(m => !(m.savedAt && (now - m.savedAt) > AUTO_DELETE_MS));

  const convo = convos.find(c=>c.id===convoId);
  const retentionMs = (convo && convo._retentionMs) || (DEFAULT_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  list = list.filter(m => m.status === 'scheduled' || (now - m.ts) <= retentionMs);
  if (list.length !== beforeLen) changed = true;

  if (changed) await setJSON('messages:'+convoId, list, true);

  const previouslySeenIds = new Set((messagesCache[convoId] || []).map(m=>m.id));
  const decrypted = [];
  for (const m of list){
    if (m.status === 'scheduled' && m.sender !== session.username) continue; // hide others' pending messages
    try{
      const plainBuf = await decryptMessage(m);
      decrypted.push({ ...m, _plainBuf: plainBuf });
    }catch(e){ /* not for us / corrupted, skip */ }
  }
  messagesCache[convoId] = decrypted;

  // Best-effort desktop notification for genuinely new incoming messages
  // while this tab isn't in view. Respects hideNotificationPreview.
  if (typeof document !== 'undefined' && document.hidden && typeof Notification !== 'undefined' && Notification.permission === 'granted'){
    for (const m of decrypted){
      if (m.sender !== session.username && m.status !== 'scheduled' && !previouslySeenIds.has(m.id) && !notifiedIds.has(m.id)){
        notifiedIds.add(m.id);
        const senderInfo = directory.find(d=>d.username===m.sender);
        const senderName = senderInfo ? senderInfo.displayName : m.sender;
        try{
          if (session.privacy.hideNotificationPreview){
            new Notification('Sealed', { body: 'New message' });
          } else {
            const preview = m.type === 'text' ? bufToStr(m._plainBuf).slice(0,80) : (m.type==='image' ? 'Sent a photo' : 'Sent a file');
            new Notification(senderName, { body: preview });
          }
        }catch(e){ /* notifications not available in this context — non-fatal */ }
      }
    }
  }
}

async function sendMessage({type, text, file}){
  const convo = convos.find(c=>c.id===activeConvoId);
  if (!convo) return;
  let bytes, filename=null, mime=null;

  if (type === 'text'){
    if (!text.trim()) return;
    bytes = strToBuf(text.trim());
  } else {
    filename = file.name; mime = file.type;
    bytes = await file.arrayBuffer();
    if (bytes.byteLength > 3 * 1024 * 1024){
      toast('That file is a bit large for encrypted storage — keep it under ~3MB.');
      return;
    }
  }

  const enc = await encryptForRecipients(new Uint8Array(bytes), convo.members);
  const msg = {
    id: randomId(),
    sender: session.username,
    ts: Date.now(),
    type,
    filename, mime,
    iv: enc.iv, ciphertext: enc.ciphertext, keys: enc.keys,
    savedAt: null,
    status: 'sent'
  };

  const list = (await getJSON('messages:'+convo.id, true)) || [];
  list.push(msg);
  await setJSON('messages:'+convo.id, list, true);

  convo.lastActivity = Date.now();
  await setJSON('convo:'+convo.id, convo, true);

  await loadMessages(convo.id);
  await loadConvos();
  render();
  flashSeal();
}

// Schedules a text message to be sent later. The message is encrypted RIGHT
// NOW (so it's never sitting around as plaintext) but marked 'scheduled' and
// hidden from everyone except the sender until scheduledFor has passed —
// see loadMessages() for the release logic. Since the sender is also one of
// the wrapped-key recipients, they can decrypt (and therefore edit) their
// own pending message at any time before it sends.
async function scheduleMessage(text, scheduledFor){
  const convo = convos.find(c=>c.id===activeConvoId);
  if (!convo || !text.trim()) return;

  const enc = await encryptForRecipients(strToBuf(text.trim()), convo.members);
  const msg = {
    id: randomId(), sender: session.username, ts: Date.now(),
    type: 'text', filename: null, mime: null,
    iv: enc.iv, ciphertext: enc.ciphertext, keys: enc.keys,
    savedAt: null, status: 'scheduled', scheduledFor
  };
  const list = (await getJSON('messages:'+convo.id, true)) || [];
  list.push(msg);
  await setJSON('messages:'+convo.id, list, true);
  await loadMessages(convo.id);
  render();
  toast('Message scheduled for ' + fmtTime(scheduledFor));
}

async function cancelScheduledMessage(msgId){
  const list = (await getJSON('messages:'+activeConvoId, true)) || [];
  const filtered = list.filter(m => m.id !== msgId);
  await setJSON('messages:'+activeConvoId, filtered, true);
  await loadMessages(activeConvoId);
  render();
}

async function markSaved(msgId){
  const list = (await getJSON('messages:'+activeConvoId, true)) || [];
  const m = list.find(x=>x.id===msgId);
  if (m && !m.savedAt){
    m.savedAt = Date.now();
    await setJSON('messages:'+activeConvoId, list, true);
    await loadMessages(activeConvoId);
    render();
  }
}

function flashSeal(){
  const el = document.querySelector('.chat-head .seal');
  if (el){ el.classList.remove('stamp'); void el.offsetWidth; el.classList.add('stamp'); }
}

// ------------------------------------------------------------------- poll

function startPolling(){
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async ()=>{
    if (!session.username) return;
    try{
      await loadConvos();
      if (activeConvoId) await loadMessages(activeConvoId);
      if (!session.username) return; // logged out while this poll was in flight
      if ($('.sidebar')){ softRefresh(); } else { render(); }
    }catch(e){ /* transient network hiccup during background poll — next tick will retry */ }
  }, 4000);
}

// --------------------------------------------------------------- rendering

function render(){
  if (!BACKEND_CONFIGURED){ renderBackendSetup(); return; }
  if (!session.username){ renderAuth(); return; }
  renderApp();
}

// Same as render(), but for actions that open/close a modal or panel over the
// CURRENT conversation (Settings, New Chat, the schedule picker) rather than
// switching to a different one. A plain render() rebuilds the composer from
// scratch and would silently wipe out whatever the user had already typed —
// exactly the same underlying bug as the original "polling wipes my draft"
// issue, just triggered by a click instead of a timer. This captures the
// textarea's value (and cursor position, if it had focus) beforehand and
// restores it into the freshly-rendered textarea afterward.
function renderPreservingDraft(){
  const before = $('#textInput');
  const draft = before ? before.value : '';
  const hadFocus = !!before && document.activeElement === before;
  const selStart = before ? before.selectionStart : null;
  const selEnd = before ? before.selectionEnd : null;
  render();
  const after = $('#textInput');
  if (after && draft){
    after.value = draft;
    if (hadFocus){
      after.focus();
      if (selStart != null) after.setSelectionRange(selStart, selEnd);
    }
  }
}

function renderBackendSetup(){
  root.innerHTML = `
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="term-bar">
          <div class="term-dot" style="background:#FF5C5C;"></div>
          <div class="term-dot" style="background:#F5C542;"></div>
          <div class="term-dot" style="background:#00FF9C;"></div>
          <div class="term-title">root@sealed:~$ setup</div>
        </div>
        <div class="auth-body">
          <div class="auth-head">
            <div class="seal">${sealSvg()}</div>
            <div class="wordmark">Seal<span>ed</span></div>
          </div>
          <div class="boot-log" style="margin-top:14px;">
            <div style="color:#F5C542;">✗ no database configured (FIREBASE_DB_URL is still a placeholder)</div>
          </div>
          <div class="auth-sub" style="margin-top:16px;">
            This app needs one small always-on database so different people's browsers can share accounts and messages. Since this page is hosted on GitHub Pages (static files only, no backend of its own), it talks to a free Firebase Realtime Database instead.<br/><br/>
            <strong style="color:var(--teal);">To finish setup:</strong><br/>
            1. Go to console.firebase.google.com → create a free project<br/>
            2. Build → Realtime Database → Create Database → start in test mode<br/>
            3. Copy the Database URL it gives you<br/>
            4. Paste it into the <code style="color:var(--seal);">FIREBASE_DB_URL</code> constant near the top of js/config.js, replacing the current value<br/><br/>
            Every message is still encrypted in your browser before it's sent — the database only ever stores ciphertext, regardless of which backend holds it.
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderAuth(){
  root.innerHTML = `
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="term-bar">
          <div class="term-dot" style="background:#FF5C5C;"></div>
          <div class="term-dot" style="background:#F5C542;"></div>
          <div class="term-dot" style="background:#00FF9C;"></div>
          <div class="term-title">root@sealed:~$</div>
        </div>
        <div class="auth-body">
        <div class="auth-head">
          <div class="seal">${sealSvg()}</div>
          <div class="wordmark">Seal<span>ed</span></div>
        </div>
        <div class="auth-sub">// private messages, sealed to whoever you send them to.<br/>encryption runs on your device — this app never sees plaintext.</div>
        <div class="tabs">
          <div class="tab ${ui.authTab==='login'?'active':''}" data-tab="login">login</div>
          <div class="tab ${ui.authTab==='signup'?'active':''}" data-tab="signup">create_account</div>
        </div>
        <form id="authForm">
          <label>username</label>
          <input type="text" id="f-username" autocomplete="username" placeholder="e.g. rayed446" />
          ${ui.authTab==='signup' ? `<label>display_name</label><input type="text" id="f-display" placeholder="what people will see" />` : ''}
          <label>passphrase</label>
          <input type="password" id="f-password" autocomplete="${ui.authTab==='signup'?'new-password':'current-password'}" placeholder="••••••••" />
          ${ui.authTab==='signup' ? `<div class="hint">min. 8 characters recommended — this is the only thing protecting your private key, nothing else guards it.</div>` : ''}
          <button class="btn" type="submit" ${ui.busy?'disabled':''}>${ui.busy ? 'working...' : (ui.authTab==='login' ? '[ log in ]' : '[ create sealed account ]')}</button>
          <div class="err">${ui.authErr ? escapeHtml(ui.authErr) : ''}</div>
        </form>
        ${ui.busy && ui.authSteps.length ? `<div class="boot-log">${ui.authSteps.map((s,i)=>`<div class="${i<ui.authSteps.length-1?'done':''}">${escapeHtml(s)}${i===ui.authSteps.length-1?' <span class="blink">_</span>':''}</div>`).join('')}</div>` : ''}
        ${ui.authTab==='signup' && !ui.busy ? `<div class="hint">your passphrase unlocks your private key — it's never stored anywhere, not even here. forget it and there's no reset: that's what makes the encryption real.</div>` : ''}
        </div>
      </div>
    </div>
  `;
  root.querySelectorAll('.tab').forEach(t=>t.addEventListener('click', ()=>{ ui.authTab = t.dataset.tab; ui.authErr=''; render(); }));
  $('#authForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const username = $('#f-username').value;
    const password = $('#f-password').value;
    const display = ui.authTab==='signup' ? $('#f-display').value : '';
    ui.authErr=''; ui.busy = true; ui.authSteps = ['initializing']; render();
    try{
      if (ui.authTab==='signup'){
        await signUp(username, display, password, (step)=>{ ui.authSteps.push(step); render(); });
      } else {
        ui.authSteps.push('deriving key from passphrase');
        render();
        await logIn(username, password);
        ui.authSteps.push('done');
      }
      await runAccountExpirySweep(); // also refreshes `directory`, so no separate loadDirectory() call needed here
      await loadConvos();
      startPolling();
      setupPrivacyListeners();
      ui.busy = false;
      render();
    }catch(err){
      ui.busy = false; ui.authSteps = []; ui.authErr = err.message || 'Something went wrong.'; render();
    }
  });
}

function sealSvg(){
  return `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 2L4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-4z" fill="#0B0D12" opacity="0.85"/>
    <path d="M8.5 12.2l2.4 2.4 4.6-4.9" stroke="#E8A33D" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function convoTitle(c){
  if (c.type==='group') return c.name;
  const other = c.members.find(m=>m!==session.username);
  const d = directory.find(x=>x.username===other);
  return d ? d.displayName : other;
}
function convoSubtitle(c){
  if (c.type==='group') return c.members.length + ' members';
  const other = c.members.find(m=>m!==session.username);
  return '@'+other;
}

function renderConvoListItems(){
  if (convos.length === 0) return `<div class="empty-side">No conversations yet. Start one — every message is sealed with your contact's public key before it leaves your browser.</div>`;
  return convos.map(c => `
    <div class="convo ${c.id===activeConvoId?'active':''}" data-id="${c.id}">
      <div class="avatar">${escapeHtml(initials(convoTitle(c)))}</div>
      <div class="convo-meta">
        <div class="convo-name">${escapeHtml(convoTitle(c))}${c.type==='group'?'<span class="badge">GROUP</span>':''}</div>
        <div class="convo-sub">${escapeHtml(convoSubtitle(c))}</div>
      </div>
    </div>
  `).join('');
}

function renderApp(){
  const activeConvo = convos.find(c=>c.id===activeConvoId);

  root.innerHTML = `
    <div class="shell">
      <div class="sidebar">
        <div class="sb-head">
          <div class="me">
            <div class="avatar">${escapeHtml(initials(session.displayName))}</div>
            <div class="me-name">${escapeHtml(session.displayName)}</div>
          </div>
          <div style="display:flex; gap:2px;">
            <button class="icon-btn" id="btnSettings" title="Settings">${gearSvg()}</button>
            <button class="icon-btn" id="btnLogout" title="Log out">${logoutSvg()}</button>
          </div>
        </div>
        <div class="sb-actions">
          <button class="btn" id="btnNewChat">New private chat</button>
        </div>
        <div class="convo-list">
          ${renderConvoListItems()}
        </div>
      </div>

      <div class="main">
        ${activeConvo ? renderChat(activeConvo) : `
          <div class="no-chat">
            <div class="seal">${sealSvg()}</div>
            <div>Pick a conversation, or start a new one.</div>
          </div>
        `}
      </div>
    </div>
    ${ui.showNewChat ? renderNewChatModal() : ''}
    ${ui.showSettings ? renderSettingsModal() : ''}
  `;

  attachAppListeners();
}

function renderChat(convo){
  const msgs = messagesCache[convo.id] || [];
  let headSub;
  if (convo.type === 'dm'){
    const otherUsername = convo.members.find(m=>m!==session.username);
    const other = directory.find(d=>d.username===otherUsername);
    headSub = 'Safety code: ' + (other ? other.fingerprint : '');
  } else {
    headSub = convo.members.length + ' members · each message sealed individually per member';
  }

  const retentionDays = convo._retentionDays || DEFAULT_RETENTION_DAYS;
  const now = Date.now();
  const soonToExpireCount = msgs.filter(m => {
    if (m.status === 'scheduled') return false;
    const cutoff = m.ts + retentionDays*24*60*60*1000;
    return cutoff - now > 0 && cutoff - now <= RETENTION_WARNING_MS;
  }).length;

  return `
    <div class="chat-head">
      <div>
        <div class="chat-head-title">${escapeHtml(convoTitle(convo))}</div>
        <div class="chat-head-sub">${escapeHtml(headSub)} · retention: ${retentionDays}d</div>
      </div>
      <div class="seal" title="Encrypted with RSA-OAEP + AES-256-GCM">${sealSvg()}</div>
    </div>
    ${soonToExpireCount > 0 ? `<div class="retention-warning">⚠ ${soonToExpireCount} message${soonToExpireCount>1?'s':''} in this chat will be auto-deleted within 24 hours (retention: ${retentionDays} days). Change this in Settings.</div>` : ''}
    <div class="messages ${session.privacy.disableSelection ? 'privacy-noselect' : ''}" id="msgList">
      ${msgs.map(m => renderMessage(m)).join('')}
    </div>
    <div class="composer-wrap">
      ${ui.showSchedule ? `
        <div class="schedule-bar">
          <input type="datetime-local" id="scheduleAt" min="${toDatetimeLocalValue(new Date(Date.now()+60000))}" value="${toDatetimeLocalValue(new Date(Date.now()+5*60000))}" />
          <button class="btn ghost" id="scheduleCancel">Cancel</button>
          <button class="btn" id="scheduleConfirm">Schedule</button>
        </div>
      ` : ''}
      <div class="composer">
        <label class="icon-btn" style="cursor:pointer;">
          ${clipSvg()}
          <input type="file" id="fileInput" style="display:none" />
        </label>
        <button class="icon-btn" id="btnScheduleToggle" title="Schedule for later">${clockSvg()}</button>
        <textarea id="textInput" rows="1" placeholder="Write a sealed message…"></textarea>
        <button class="send-btn" id="btnSend">${sendSvg()}</button>
      </div>
    </div>
  `;
}

function renderMessage(m){
  const mine = m.sender === session.username;
  const senderInfo = directory.find(d=>d.username===m.sender);
  const senderName = mine ? 'You' : (senderInfo ? senderInfo.displayName : m.sender);
  const isPending = m.status === 'scheduled';
  let body = '';

  if (m.type === 'text'){
    body = `<div>${escapeHtml(bufToStr(m._plainBuf))}</div>`;
  } else {
    const blob = new Blob([m._plainBuf], { type: m.mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    if (m.type === 'image'){
      body = `<div><img src="${url}" /></div>`;
    } else {
      body = `<a class="file-chip" href="${url}" download="${escapeHtml(m.filename||'file')}" data-download-id="${m.id}">${fileSvg()} ${escapeHtml(m.filename||'file')}</a>`;
    }
  }

  if (isPending){
    return `
      <div class="msg-row mine">
        <div class="msg-sender">You (pending)</div>
        <div class="bubble pending">${body}</div>
        <div class="msg-foot">
          <span class="msg-time">${clockSvg()} sends ${fmtTime(m.scheduledFor)}</span>
          <button class="save-btn" data-edit-scheduled="${m.id}">Edit</button>
          <button class="save-btn" data-cancel-scheduled="${m.id}">Cancel</button>
        </div>
      </div>
    `;
  }

  const savedMarkup = m.savedAt
    ? `<span class="save-btn saved"><span class="ring"></span> deletes ${timeLeft(m.savedAt)}</span>`
    : `<button class="save-btn" data-save-id="${m.id}">Save</button>`;

  return `
    <div class="msg-row ${mine?'mine':'theirs'}">
      <div class="msg-sender">${escapeHtml(senderName)}</div>
      <div class="bubble">${body}</div>
      <div class="msg-foot">
        <span class="msg-time">${fmtTime(m.ts)}</span>
        ${savedMarkup}
      </div>
    </div>
  `;
}

function timeLeft(savedAt){
  const rem = AUTO_DELETE_MS - (Date.now() - savedAt);
  const mins = Math.max(0, Math.ceil(rem/60000));
  return 'in ' + mins + 'm';
}

function renderNewChatModal(){
  const others = directory.filter(d=>d.username!==session.username);
  return `
    <div class="modal-bg" id="modalBg">
      <div class="modal">
        <h3>New private chat</h3>
        <div class="modal-sub">Pick one person for a 1:1 chat, or several to start a group. Every message is sealed individually to each person's key.</div>
        <div class="user-list">
          ${others.length===0 ? `<div class="empty-side">Nobody else has joined yet — share this page with a friend so they can create an account.</div>` : ''}
          ${others.map(d => `
            <label class="user-pick">
              <input type="checkbox" value="${escapeHtml(d.username)}" ${ui.picked.includes(d.username)?'checked':''} />
              <div class="avatar">${escapeHtml(initials(d.displayName))}</div>
              <div>
                <div style="font-size:13.5px;font-weight:600;">${escapeHtml(d.displayName)}</div>
                <div style="font-size:11px;color:var(--muted);font-family:var(--mono);">@${escapeHtml(d.username)}</div>
              </div>
            </label>
          `).join('')}
        </div>
        ${ui.picked.length > 1 ? `<input type="text" id="groupName" placeholder="Group name" style="margin-bottom:14px;" />` : ''}
        <div class="modal-footer">
          <button class="btn ghost" id="modalCancel" style="flex:1;">Cancel</button>
          <button class="btn" id="modalGo" style="flex:1;" ${ui.picked.length===0?'disabled':''}>${ui.picked.length>1?'Create group':'Start chat'}</button>
        </div>
      </div>
    </div>
  `;
}

function renderSettingsModal(){
  const p = session.privacy;
  return `
    <div class="modal-bg" id="settingsBg">
      <div class="modal">
        <h3>Settings</h3>
        <div class="modal-sub">These apply to your account across every conversation.</div>
        <div class="user-list" style="padding-right:4px;">

          <div class="settings-section">
            <div class="settings-label">Message retention</div>
            <div class="hint" style="margin:0 0 8px;">How long conversation history sticks around. Applied per-chat as the shorter of your setting and the other person's.</div>
            <select id="retentionSelect">
              ${RETENTION_OPTIONS_DAYS.map(d => `<option value="${d}" ${session.retentionDays===d?'selected':''}>${d} days</option>`).join('')}
            </select>
          </div>

          <div class="settings-section">
            <div class="settings-label">Privacy mode</div>
            <label class="setting-row">
              <input type="checkbox" id="privBlur" ${p.blurOnBlur?'checked':''} />
              <span>Blur chat when this tab loses focus</span>
            </label>
            <label class="setting-row">
              <input type="checkbox" id="privNoSelect" ${p.disableSelection?'checked':''} />
              <span>Disable text selection in chat</span>
            </label>
            <label class="setting-row">
              <input type="checkbox" id="privHidePreview" ${p.hideNotificationPreview?'checked':''} />
              <span>Hide message text in notifications</span>
            </label>
            <button class="btn ghost" id="btnEnableNotifs" style="margin-top:10px;">Enable browser notifications</button>
            <div class="privacy-disclaimer">⚠ No website — including this one — can prevent screenshots, screen recordings, or someone photographing their screen. These settings reduce accidental exposure only; they are not real screenshot protection.</div>
          </div>

          <div class="settings-section">
            <div class="settings-label">Account</div>
            <div class="hint">Signed in as <strong style="color:var(--text);">@${escapeHtml(session.username)}</strong>. If this account doesn't log in for ${ACCOUNT_EXPIRY_DAYS} days, it's automatically removed (best-effort — depends on someone's browser being open to run the cleanup).</div>
          </div>

        </div>
        <div class="modal-footer">
          <button class="btn ghost" id="settingsClose" style="flex:1;">Close</button>
          <button class="btn" id="settingsSave" style="flex:1;">Save</button>
        </div>
      </div>
    </div>
  `;
}

function gearSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>`; }
function clockSvg(){ return `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>`; }

function logoutSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>`; }
function clipSvg(){ return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a5 5 0 01-7.07-7.07l9.19-9.19a3.5 3.5 0 014.95 4.95L9.41 17.86a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>`; }
function sendSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0B0D12" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>`; }
function fileSvg(){ return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>`; }

function attachConvoListListeners(){
  root.querySelectorAll('.convo').forEach(el=>{
    el.addEventListener('click', async ()=>{
      activeConvoId = el.dataset.id;
      await safely(async ()=>{
        const c = convos.find(x=>x.id===activeConvoId);
        if (c && !c._retentionMs) await computeEffectiveRetentionMs(c);
        await loadMessages(activeConvoId);
        renderApp(); // switching chats is a deliberate nav action, so a full rebuild is fine here
        const list = $('#msgList'); if (list) list.scrollTop = list.scrollHeight;
      }, 'Could not load that conversation — check your connection and try again.');
    });
  });
}

function attachMessageListeners(){
  root.querySelectorAll('[data-save-id]').forEach(el=>{
    el.addEventListener('click', ()=> safely(()=>markSaved(el.dataset.saveId), 'Could not save that message right now.'));
  });
  root.querySelectorAll('[data-download-id]').forEach(el=>{
    el.addEventListener('click', ()=> setTimeout(()=>safely(()=>markSaved(el.dataset.downloadId), 'Could not mark that download as saved.'), 300));
  });
  root.querySelectorAll('[data-cancel-scheduled]').forEach(el=>{
    el.addEventListener('click', ()=> safely(()=>cancelScheduledMessage(el.dataset.cancelScheduled), 'Could not cancel that scheduled message.'));
  });
  root.querySelectorAll('[data-edit-scheduled]').forEach(el=>{
    el.addEventListener('click', ()=> safely(async ()=>{
      const convo = convos.find(c=>c.id===activeConvoId);
      const msg = (messagesCache[activeConvoId]||[]).find(m=>m.id===el.dataset.editScheduled);
      if (!msg) return;
      const text = bufToStr(msg._plainBuf);
      await cancelScheduledMessage(msg.id);
      ui.showSchedule = true;
      render();
      const ti = $('#textInput'); if (ti) ti.value = text;
      const sa = $('#scheduleAt'); if (sa) sa.value = toDatetimeLocalValue(new Date(msg.scheduledFor));
    }, 'Could not load that scheduled message for editing.'));
  });
}

// Refreshes the conversation list + message list in place, WITHOUT touching the
// composer's DOM node. Used by background polling so a message you're actively
// typing (and your cursor focus) never gets wiped out mid-keystroke — the old
// bug was that every background poll did a full innerHTML rebuild, which
// silently destroyed and recreated the textarea every few seconds.
function softRefresh(){
  if (!BACKEND_CONFIGURED || !session.username) return;
  const convoListEl = $('.convo-list');
  if (convoListEl){
    convoListEl.innerHTML = renderConvoListItems();
    attachConvoListListeners();
  }
  const activeConvo = convos.find(c=>c.id===activeConvoId);
  const msgListEl = $('#msgList');
  if (msgListEl && activeConvo){
    const wasNearBottom = (msgListEl.scrollHeight - msgListEl.scrollTop - msgListEl.clientHeight) < 60;
    msgListEl.innerHTML = (messagesCache[activeConvo.id] || []).map(m => renderMessage(m)).join('');
    attachMessageListeners();
    if (wasNearBottom) msgListEl.scrollTop = msgListEl.scrollHeight;
  }
}

// ------------------------------------------------------------- listeners

function attachAppListeners(){
  $('#btnLogout')?.addEventListener('click', logOut);
  $('#btnNewChat')?.addEventListener('click', ()=>{ ui.showNewChat = true; ui.showSettings = false; ui.picked=[]; renderPreservingDraft(); });
  $('#btnSettings')?.addEventListener('click', ()=>{ ui.showSettings = true; ui.showNewChat = false; renderPreservingDraft(); });

  attachConvoListListeners();

  const msgList = $('#msgList');
  if (msgList) msgList.scrollTop = msgList.scrollHeight;

  attachMessageListeners();
  applyPrivacyModeNow();

  const textInput = $('#textInput');
  const btnSend = $('#btnSend');
  const fileInput = $('#fileInput');
  const btnScheduleToggle = $('#btnScheduleToggle');

  if (textInput){
    textInput.addEventListener('keydown', (e)=>{
      if (e.key==='Enter' && !e.shiftKey){ e.preventDefault(); doSendText(); }
    });
  }
  if (btnSend) btnSend.addEventListener('click', doSendText);
  if (btnScheduleToggle) btnScheduleToggle.addEventListener('click', ()=>{ ui.showSchedule = !ui.showSchedule; renderPreservingDraft(); });
  if (fileInput) fileInput.addEventListener('change', async (e)=>{
    const file = e.target.files[0];
    if (!file) return;
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    await safely(async ()=>{ await sendMessage({type, file}); }, 'Could not send that file — check your connection and try again.');
    fileInput.value = '';
  });

  $('#scheduleCancel')?.addEventListener('click', ()=>{ ui.showSchedule = false; renderPreservingDraft(); });
  $('#scheduleConfirm')?.addEventListener('click', async ()=>{
    const text = textInput.value;
    const atVal = $('#scheduleAt')?.value;
    if (!text.trim() || !atVal) return;
    const scheduledFor = new Date(atVal).getTime();
    if (scheduledFor <= Date.now()){ toast('Pick a time in the future.'); return; }
    textInput.value = ''; ui.showSchedule = false;
    await safely(()=>scheduleMessage(text, scheduledFor), 'Could not schedule that message — check your connection and try again.');
  });

  async function doSendText(){
    const text = textInput.value;
    if (!text.trim()) return;
    textInput.value = '';
    await safely(async ()=>{ await sendMessage({type:'text', text}); }, 'Message did not send — check your connection and try again.');
  }

  // new-chat modal
  $('#modalBg')?.addEventListener('click', (e)=>{ if (e.target.id==='modalBg'){ ui.showNewChat=false; renderPreservingDraft(); } });
  $('#modalCancel')?.addEventListener('click', ()=>{ ui.showNewChat=false; renderPreservingDraft(); });
  root.querySelectorAll('.user-pick input').forEach(cb=>{
    cb.addEventListener('change', ()=>{
      if (cb.checked) ui.picked.push(cb.value);
      else ui.picked = ui.picked.filter(u=>u!==cb.value);
      ui.showNewChat = true; // keep modal open across the re-render
      renderPreservingDraft();
    });
  });
  $('#modalGo')?.addEventListener('click', async ()=>{
    ui.showNewChat = false;
    await safely(async ()=>{
      if (ui.picked.length === 1){
        await openOrCreateDM(ui.picked[0]);
      } else if (ui.picked.length > 1){
        const name = $('#groupName')?.value || '';
        await createGroup(name, ui.picked);
      }
    }, 'Could not start that chat — check your connection and try again.');
    ui.picked = [];
  });

  // settings modal
  $('#settingsBg')?.addEventListener('click', (e)=>{ if (e.target.id==='settingsBg'){ ui.showSettings=false; renderPreservingDraft(); } });
  $('#settingsClose')?.addEventListener('click', ()=>{ ui.showSettings=false; renderPreservingDraft(); });
  $('#btnEnableNotifs')?.addEventListener('click', async ()=>{
    if (typeof Notification === 'undefined'){ toast('Notifications are not supported in this browser.'); return; }
    const perm = await Notification.requestPermission();
    toast(perm === 'granted' ? 'Notifications enabled.' : 'Notifications were not enabled.');
  });
  $('#settingsSave')?.addEventListener('click', ()=> safely(async ()=>{
    const retentionDays = parseInt($('#retentionSelect')?.value, 10) || DEFAULT_RETENTION_DAYS;
    const privacy = {
      blurOnBlur: !!$('#privBlur')?.checked,
      disableSelection: !!$('#privNoSelect')?.checked,
      hideNotificationPreview: !!$('#privHidePreview')?.checked
    };
    const account = await getJSON('account:'+session.username, true);
    if (account){
      account.retentionDays = retentionDays;
      account.privacy = privacy;
      await setJSON('account:'+session.username, account, true);
    }
    session.retentionDays = retentionDays;
    session.privacy = privacy;
    convos.forEach(c => { c._retentionMs = null; c._retentionDays = null; }); // recompute next time each chat opens
    applyPrivacyModeNow();
    ui.showSettings = false;
    renderPreservingDraft();
    toast('Settings saved.');
  }, 'Could not save settings — check your connection and try again.'));
}

// Applies (or removes) the tab-blur/no-select privacy CSS classes based on
// the current session's settings and the tab's current visibility/focus.
function applyPrivacyModeNow(){
  const msgListEl = $('#msgList');
  if (!msgListEl) return;
  const shouldBlur = session.privacy.blurOnBlur && (document.hidden || !document.hasFocus());
  msgListEl.classList.toggle('privacy-blur', !!shouldBlur);
  msgListEl.classList.toggle('privacy-noselect', !!session.privacy.disableSelection);
}

// Wired up once after a successful login/signup.
function setupPrivacyListeners(){
  document.addEventListener('visibilitychange', applyPrivacyModeNow);
  window.addEventListener('blur', applyPrivacyModeNow);
  window.addEventListener('focus', applyPrivacyModeNow);
}

render();
