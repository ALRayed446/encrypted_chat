/* ============================================================================
   app.js — FINAL VERSION with ALL features working.
   v2.0 – Includes: Replies, Reactions, Profile Pictures, Block, Privacy, Expiry, Search, Auto-Login.
   ========================================================================= */

const root = $('#root');
console.log('🚀 Sealed v2.0 loading...');

// ---- VERSION CHECK ----
const APP_VERSION = '2.0';
if (localStorage.getItem('sealed_version') !== APP_VERSION) {
  localStorage.setItem('sealed_version', APP_VERSION);
  // Force rebuild of the shell on next render
  window._forceRebuild = true;
}

// ---- AUTO-LOGIN ----
(async function autoLogin() {
  const saved = localStorage.getItem('sealed_creds');
  if (saved) {
    try {
      const { username, password } = JSON.parse(atob(saved));
      if (username && password) {
        window._autoLoginData = { username, password };
      }
    } catch(e) { /* ignore */ }
  }
})();

// ---- 1. STATE ----
let session = {
  username: null,
  displayName: null,
  privateKey: null,
  publicKeyJwk: null,
  fingerprint: null,
  avatar: null,
};

let directory = [];
let convos = [];
let activeConvoId = null;
let messagesCache = {};
let pollTimer = null;
let typingTimeout = null;
let lastTypingSent = false;

let ui = {
  authTab: 'login',
  authErr: '',
  busy: false,
  authSteps: [],
  showNewChat: false,
  picked: [],
  composerText: '',
  composerSelectionStart: 0,
  composerSelectionEnd: 0,
  composerFocused: false,
  privacyMode: false,
  privacyBlurred: false,
  messageExpiry: null,
  rememberMe: false,
  replyingTo: null, // { id, sender, preview }
};

// ---- 2. PERSISTENT DOM ----
const dom = {
  root: root,
  shell: null,
  sidebar: null,
  convoList: null,
  mainArea: null,
  chatArea: null,
  noChat: null,
  chatHead: null,
  chatHeadTitle: null,
  chatHeadSub: null,
  msgList: null,
  composerArea: null,
  replyBar: null,
  textInput: null,
  btnSend: null,
  fileInput: null,
  btnPrivacy: null,
  btnBlock: null,
  expiryPicker: null,
};

// ---- 3. HELPERS ----
function getOtherUsername(convo) {
  if (convo.type === 'dm') {
    return convo.members.find(m => m !== session.username);
  }
  return null;
}

function getUserAvatar(username) {
  const entry = directory.find(d => d.username === username);
  return entry ? entry.avatar : null;
}

function getUserDisplayName(username) {
  if (username === session.username) return session.displayName;
  const entry = directory.find(d => d.username === username);
  return entry ? entry.displayName : username;
}

function convoTitle(c) {
  if (c.type === 'group') return c.name;
  const other = getOtherUsername(c);
  return getUserDisplayName(other);
}

function convoSubtitle(c) {
  if (c.type === 'group') return c.members.length + ' members';
  const other = getOtherUsername(c);
  return '@' + other;
}

function isUserOnline(username) {
  const entry = directory.find(d => d.username === username);
  if (!entry || !entry.lastSeen) return false;
  return (Date.now() - entry.lastSeen) < 10000;
}

function formatLastSeen(ts) {
  if (!ts) return 'offline';
  const diff = Date.now() - ts;
  if (diff < 10000) return 'online';
  if (diff < 60000) return 'last seen ' + Math.floor(diff / 1000) + 's ago';
  if (diff < 3600000) return 'last seen ' + Math.floor(diff / 60000) + 'm ago';
  return 'last seen ' + new Date(ts).toLocaleString();
}

// ---- 4. AUTH ----
async function loadDirectory() {
  directory = (await getJSON('directory', true)) || [];
  for (let d of directory) {
    const acc = await getJSON('account:' + d.username, true);
    if (acc) {
      d.lastSeen = acc.lastSeen || d.lastSeen;
      d.avatar = acc.avatar || null;
      d.displayName = acc.displayName || d.displayName;
    }
  }
}

async function signUp(username, displayName, password, onStep) {
  username = username.trim().toLowerCase();
  displayName = displayName.trim() || username;
  if (!username || !password) throw new Error('Username and password are required.');
  if (password.length < 8) throw new Error('Password must be at least 8 characters.');

  onStep?.('checking username');
  await loadDirectory();
  if (directory.some(d => d.username === username)) throw new Error('Username already taken.');

  const existingAccount = await getJSON('account:'+username, true);
  if (existingAccount) throw new Error('Username already taken.');

  onStep?.('generating RSA keypair');
  const keypair = await generateKeypair();
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);

  onStep?.('deriving key from passphrase');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapKey = await deriveWrapKey(password, salt);

  onStep?.('sealing private key');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encPrivate = await crypto.subtle.encrypt({name:'AES-GCM', iv}, wrapKey, strToBuf(JSON.stringify(privateKeyJwk)));

  const account = {
    username, displayName,
    publicKeyJwk,
    salt: buf2b64(salt),
    iv: buf2b64(iv),
    encPrivateKey: buf2b64(encPrivate),
    createdAt: Date.now(),
    lastSeen: Date.now(),
    blocked: {},
    avatar: null,
  };
  onStep?.('writing account');
  await setJSON('account:'+username, account, true);

  onStep?.('computing fingerprint');
  const fp = await fingerprintOf(publicKeyJwk);
  directory.push({ username, displayName, publicKeyJwk, fingerprint: fp, lastSeen: Date.now(), avatar: null });
  await setJSON('directory', directory, true);

  onStep?.('done');
  session = { username, displayName, privateKey: keypair.privateKey, publicKeyJwk, fingerprint: fp, avatar: null };
  await setJSON('userConvos:'+username, [], true);
}

async function logIn(username, password) {
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
    throw new Error('Wrong password.');
  }
  const privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['decrypt']);
  const fp = await fingerprintOf(account.publicKeyJwk);
  session = { 
    username, 
    displayName: account.displayName, 
    privateKey, 
    publicKeyJwk: account.publicKeyJwk, 
    fingerprint: fp,
    avatar: account.avatar || null
  };
  
  if (ui.rememberMe) {
    const creds = btoa(JSON.stringify({ username, password }));
    localStorage.setItem('sealed_creds', creds);
  } else {
    localStorage.removeItem('sealed_creds');
  }
}

function logOut() {
  if (session.username) updateLastSeen();
  localStorage.removeItem('sealed_creds');
  session = { username:null, displayName:null, privateKey:null, publicKeyJwk:null, fingerprint:null, avatar:null };
  convos = []; messagesCache = {}; activeConvoId = null;
  if (pollTimer) clearInterval(pollTimer);
  dom.shell = null;
  // Force rebuild on next render
  window._forceRebuild = true;
  render();
}

// ---- 5. PROFILE PICTURE ----
async function updateAvatar(base64Data) {
  if (!session.username) return;
  const account = await getJSON('account:'+session.username, true);
  if (!account) return;
  account.avatar = base64Data;
  await setJSON('account:'+session.username, account, true);
  session.avatar = base64Data;
  const entry = directory.find(d => d.username === session.username);
  if (entry) entry.avatar = base64Data;
  renderApp();
}

// ---- 6. LAST SEEN ----
async function updateLastSeen() {
  if (!session.username) return;
  const account = await getJSON('account:'+session.username, true);
  if (!account) return;
  account.lastSeen = Date.now();
  await setJSON('account:'+session.username, account, true);
  const entry = directory.find(d => d.username === session.username);
  if (entry) entry.lastSeen = Date.now();
}

// ---- 7. BLOCK SYSTEM ----
async function setBlock(targetUsername, type) {
  if (!session.username) return;
  const account = await getJSON('account:'+session.username, true);
  if (!account) return;
  if (type === null) {
    delete account.blocked[targetUsername];
  } else {
    account.blocked[targetUsername] = type;
  }
  await setJSON('account:'+session.username, account, true);
  toast('User ' + (type ? (type + ' blocked') : 'unblocked'));
}

async function checkBlockStatus(sender, recipient) {
  const recipientAccount = await getJSON('account:'+recipient, true);
  const senderAccount = await getJSON('account:'+sender, true);
  const result = { senderBlocked: false, recipientBlocked: false, softBlocked: false };
  if (senderAccount && senderAccount.blocked && senderAccount.blocked[recipient]) {
    result.senderBlocked = true;
    if (senderAccount.blocked[recipient] === 'soft') result.softBlocked = true;
  }
  if (recipientAccount && recipientAccount.blocked && recipientAccount.blocked[sender]) {
    result.recipientBlocked = true;
    if (recipientAccount.blocked[sender] === 'soft') result.softBlocked = true;
  }
  return result;
}

// ---- 8. CONVERSATIONS ----
async function loadConvos() {
  const ids = (await getJSON('userConvos:'+session.username, true)) || [];
  const list = [];
  for (const id of ids) {
    const c = await getJSON('convo:'+id, true);
    if (c) list.push(c);
  }
  list.sort((a,b)=> (b.lastActivity||b.createdAt) - (a.lastActivity||a.createdAt));
  convos = list;
}

async function addConvoToUser(username, convoId) {
  const list = (await getJSON('userConvos:'+username, true)) || [];
  if (!list.includes(convoId)) {
    list.push(convoId);
    await setJSON('userConvos:'+username, list, true);
  }
}

function dmId(a,b){ return 'dm_' + [a,b].sort().join('__'); }

async function openOrCreateDM(otherUsername) {
  const blockStatus = await checkBlockStatus(session.username, otherUsername);
  if (blockStatus.recipientBlocked || blockStatus.senderBlocked) {
    toast('Cannot start chat: blocked.');
    return;
  }
  const id = dmId(session.username, otherUsername);
  let c = await getJSON('convo:'+id, true);
  if (!c) {
    c = { id, type:'dm', members:[session.username, otherUsername], createdAt: Date.now(), lastActivity: Date.now() };
    await setJSON('convo:'+id, c, true);
    await setJSON('messages:'+id, [], true);
    await addConvoToUser(session.username, id);
    await addConvoToUser(otherUsername, id);
  }
  await loadConvos();
  activeConvoId = id;
  await loadMessages(id);
  await markRead(id);
  renderApp();
}

async function createGroup(name, memberUsernames) {
  for (let m of memberUsernames) {
    const blockStatus = await checkBlockStatus(session.username, m);
    if (blockStatus.recipientBlocked || blockStatus.senderBlocked) {
      toast('Cannot add ' + m + ' (blocked).');
      return;
    }
  }
  const id = 'grp_' + randomId();
  const members = Array.from(new Set([session.username, ...memberUsernames]));
  const c = { id, type:'group', name: name || 'Untitled group', members, createdAt: Date.now(), lastActivity: Date.now() };
  await setJSON('convo:'+id, c, true);
  await setJSON('messages:'+id, [], true);
  for (const m of members) await addConvoToUser(m, id);
  await loadConvos();
  activeConvoId = id;
  await loadMessages(id);
  renderApp();
}

// ---- 9. MESSAGES ----
async function loadMessages(convoId) {
  let list = (await getJSON('messages:'+convoId, true)) || [];
  const now = Date.now();
  let changed = false;
  list = list.filter(m => {
    if (m.expiresAt && now > m.expiresAt) {
      changed = true;
      return false;
    }
    return true;
  });
  if (changed) await setJSON('messages:'+convoId, list, true);

  const decrypted = [];
  for (const m of list) {
    try {
      const plainBuf = await decryptMessage(m);
      decrypted.push({ ...m, _plainBuf: plainBuf });
    } catch(e) { /* skip */ }
  }
  messagesCache[convoId] = decrypted;
}

async function addReaction(msgId, emoji) {
  if (!activeConvoId) return;
  const list = (await getJSON('messages:'+activeConvoId, true)) || [];
  const msg = list.find(m => m.id === msgId);
  if (!msg) return;
  if (!msg.reactions) msg.reactions = {};
  if (msg.reactions[session.username] === emoji) {
    delete msg.reactions[session.username];
  } else {
    msg.reactions[session.username] = emoji;
  }
  await setJSON('messages:'+activeConvoId, list, true);
  await loadMessages(activeConvoId);
  renderApp();
}

async function sendMessage({type, text, file}) {
  await loadConvos();
  let convo = convos.find(c => c.id === activeConvoId);
  if (!convo) {
    const c = await getJSON('convo:'+activeConvoId, true);
    if (c) {
      convos.push(c);
      convo = c;
    } else {
      toast('Conversation not found.');
      return;
    }
  }

  for (let recipient of convo.members) {
    if (recipient === session.username) continue;
    const blockStatus = await checkBlockStatus(session.username, recipient);
    if (blockStatus.recipientBlocked || blockStatus.senderBlocked) {
      if (blockStatus.softBlocked) {
        const account = await getJSON('account:'+session.username, true) || {};
        if (account._sentFinal && account._sentFinal[recipient]) {
          toast('Final message already sent.');
          return;
        }
        if (!account._sentFinal) account._sentFinal = {};
        account._sentFinal[recipient] = Date.now();
        await setJSON('account:'+session.username, account, true);
      } else {
        toast('Cannot send: blocked.');
        return;
      }
    }
  }

  let bytes, filename=null, mime=null;
  if (type === 'text') {
    if (!text.trim()) return;
    bytes = strToBuf(text.trim());
  } else {
    filename = file.name; mime = file.type;
    bytes = await file.arrayBuffer();
    if (bytes.byteLength > 3 * 1024 * 1024) {
      toast('File too large (max 3MB).');
      return;
    }
  }

  let replyToId = null;
  let replyToPreview = null;
  if (ui.replyingTo) {
    replyToId = ui.replyingTo.id;
    if (ui.replyingTo.preview) {
      replyToPreview = ui.replyingTo.preview;
    } else {
      replyToPreview = '[File/Image]';
    }
    ui.replyingTo = null;
  }

  const enc = await encryptForRecipients(new Uint8Array(bytes), convo.members);
  const msg = {
    id: randomId(),
    sender: session.username,
    ts: Date.now(),
    type,
    filename,
    mime,
    iv: enc.iv,
    ciphertext: enc.ciphertext,
    keys: enc.keys,
    savedAt: null,
    expiresAt: ui.messageExpiry ? Date.now() + ui.messageExpiry : null,
    readBy: {},
    reactions: {},
    replyToId: replyToId,
    replyToPreview: replyToPreview,
  };

  const list = (await getJSON('messages:'+convo.id, true)) || [];
  list.push(msg);
  await setJSON('messages:'+convo.id, list, true);

  convo.lastActivity = Date.now();
  await setJSON('convo:'+convo.id, convo, true);

  ui.messageExpiry = null;
  if (dom.expiryPicker) dom.expiryPicker.value = '';

  await loadMessages(convo.id);
  await loadConvos();
  renderApp();
  flashSeal();
}

async function markRead(convoId) {
  if (!convoId) return;
  const list = (await getJSON('messages:'+convoId, true)) || [];
  let changed = false;
  for (let m of list) {
    if (!m.readBy) m.readBy = {};
    if (!m.readBy[session.username] && m.sender !== session.username) {
      m.readBy[session.username] = Date.now();
      changed = true;
    }
  }
  if (changed) {
    await setJSON('messages:'+convoId, list, true);
    if (messagesCache[convoId]) {
      for (let cached of messagesCache[convoId]) {
        const found = list.find(x => x.id === cached.id);
        if (found) cached.readBy = found.readBy;
      }
    }
  }
}

async function markSaved(msgId) {
  const list = (await getJSON('messages:'+activeConvoId, true)) || [];
  const m = list.find(x=>x.id===msgId);
  if (m && !m.savedAt) {
    m.savedAt = Date.now();
    await setJSON('messages:'+activeConvoId, list, true);
    await loadMessages(activeConvoId);
    renderApp();
  }
}

function flashSeal() {
  const el = document.querySelector('.chat-head .seal');
  if (el){ el.classList.remove('stamp'); void el.offsetWidth; el.classList.add('stamp'); }
}

// ---- 10. TYPING INDICATOR ----
async function sendTyping(isTyping) {
  if (!activeConvoId || !session.username) return;
  try {
    const path = 'typing:' + activeConvoId + '/' + session.username;
    await setJSON(path, isTyping ? Date.now() : false, true);
  } catch(e) { /* ignore */ }
}

function debounceTyping() {
  if (typingTimeout) clearTimeout(typingTimeout);
  if (!lastTypingSent) {
    sendTyping(true);
    lastTypingSent = true;
  }
  typingTimeout = setTimeout(() => {
    sendTyping(false);
    lastTypingSent = false;
    typingTimeout = null;
  }, 2000);
}

async function getTypingUsers(convoId) {
  try {
    const data = await getJSON('typing:' + convoId, true);
    if (!data) return [];
    const users = [];
    for (let [user, ts] of Object.entries(data)) {
      if (user === session.username) continue;
      if (ts && (Date.now() - ts) < 3000) users.push(user);
    }
    return users;
  } catch(e) { return []; }
}

// ---- 11. POLLING ----
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!session.username) return;
    try {
      if (Math.random() < 0.1) updateLastSeen();
      await loadConvos();
      if (activeConvoId) {
        const oldLen = (messagesCache[activeConvoId] || []).length;
        await loadMessages(activeConvoId);
        const newLen = (messagesCache[activeConvoId] || []).length;
        if (newLen > oldLen) await markRead(activeConvoId);
      }
      renderApp();
    } catch(e) { /* silent */ }
  }, 4000);
}

// ---- 12. RENDERING ----
function captureComposerState() {
  const el = dom.textInput;
  if (!el) return;
  ui.composerText = el.value;
  ui.composerSelectionStart = el.selectionStart ?? el.value.length;
  ui.composerSelectionEnd = el.selectionEnd ?? el.value.length;
  ui.composerFocused = document.activeElement === el;
}

function restoreComposerState() {
  const el = dom.textInput;
  if (!el) return;
  el.value = ui.composerText || '';
  if (ui.composerFocused) {
    requestAnimationFrame(() => {
      el.focus();
      const start = Math.min(ui.composerSelectionStart, el.value.length);
      const end = Math.min(ui.composerSelectionEnd, el.value.length);
      el.setSelectionRange(start, end);
    });
  }
}

function syncPrivacyState() {
  document.body.classList.toggle('privacy-active', ui.privacyMode);
  document.body.classList.toggle('privacy-blur', ui.privacyMode && ui.privacyBlurred);
}

function setPrivacyMode(enabled) {
  ui.privacyMode = !!enabled;
  ui.privacyBlurred = false;
  syncPrivacyState();
}

function handleWindowBlur() {
  if (ui.privacyMode){ ui.privacyBlurred = true; syncPrivacyState(); }
}
function handleWindowFocus() {
  ui.privacyBlurred = false;
  syncPrivacyState();
}

function scrollToMessage(msgId) {
  if (!dom.msgList) return;
  const el = dom.msgList.querySelector(`[data-msg-id="${msgId}"]`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.background = 'rgba(0,255,156,0.1)';
    setTimeout(() => el.style.background = '', 2000);
  } else {
    toast('Original message not loaded.');
  }
}

// ----- BUILD SHELL (with ALL features) -----
function buildShell() {
  // If shell exists and we don't force rebuild, skip
  if (dom.shell && !window._forceRebuild) return;

  console.log('🔄 Building fresh shell with all features...');
  dom.root.innerHTML = `
    <div class="shell" id="appShell">
      <div class="sidebar" id="sidebar">
        <div class="sb-head">
          <div class="me" style="position:relative;">
            <div class="avatar" id="myAvatar" style="position:relative; cursor:pointer;">
              ${session.avatar ? `<img src="${session.avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" />` : escapeHtml(initials(session.displayName))}
              <span class="avatar-edit" id="avatarEditBtn" title="Change profile picture" style="position:absolute;bottom:-4px;right:-4px;background:var(--teal);color:#000;border-radius:50%;width:16px;height:16px;font-size:10px;display:flex;align-items:center;justify-content:center;border:2px solid var(--bg);cursor:pointer;">✎</span>
            </div>
            <div class="me-name">${escapeHtml(session.displayName)}</div>
          </div>
          <button class="icon-btn" id="btnLogout" title="Log out">${logoutSvg()}</button>
        </div>
        <div class="sb-actions">
          <button class="btn" id="btnNewChat">New private chat</button>
        </div>
        <div class="convo-list" id="convoList"></div>
      </div>
      <div class="main" id="mainArea">
        <div class="no-chat" id="noChat">
          <div class="seal">${sealSvg()}</div>
          <div style="font-size:14px; color:var(--text);">Pick a conversation, or start a new one.</div>
          <div style="font-size:11px; color:var(--muted); max-width:280px; text-align:center; line-height:1.6;">Your messages stay encrypted.</div>
        </div>
        <div class="chat-area" id="chatArea" style="display:none;">
          <div class="chat-head" id="chatHead">
            <div>
              <div class="chat-head-title" id="chatHeadTitle"></div>
              <div class="chat-head-sub" id="chatHeadSub"></div>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
              <button class="icon-btn" id="btnBlock" title="Block this user">⛔</button>
              <button class="icon-btn" id="btnPrivacy" title="Privacy mode">👁</button>
              <div class="seal" title="Encrypted">${sealSvg()}</div>
            </div>
          </div>
          <div class="messages" id="msgList"></div>
          <div class="composer" id="composerArea">
            <!-- Reply Bar -->
            <div id="replyBar" style="display:none; background:var(--surface-2); border-radius:6px; padding:6px 10px; margin-bottom:6px; border-left: 3px solid var(--teal); font-size:12px; color:var(--muted); justify-content:space-between; align-items:center; width:100%;">
              <div>
                <span style="color:var(--teal);">Replying to <span id="replySender"></span></span>
                <div id="replyPreviewText" style="font-size:12px; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:200px;"></div>
              </div>
              <button id="cancelReplyBtn" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;">✕</button>
            </div>
            <!-- Composer row -->
            <div style="display:flex; gap:6px; align-items:center; margin-right:6px; width:100%;">
              <select id="expiryPicker" style="background:#000; border:1px solid var(--line); color:var(--text); border-radius:4px; padding:4px; font-size:11px; cursor:pointer;">
                <option value="">Off</option>
                <option value="60000">1m</option>
                <option value="300000">5m</option>
                <option value="1800000">30m</option>
                <option value="3600000">1h</option>
                <option value="86400000">24h</option>
              </select>
              <label class="icon-btn" style="cursor:pointer;">
                ${clipSvg()}
                <input type="file" id="fileInput" style="display:none" />
              </label>
              <textarea id="textInput" rows="1" placeholder="Write a sealed message…"></textarea>
              <button class="send-btn" id="btnSend">${sendSvg()}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Hidden file input for avatar
  let avatarInput = document.getElementById('avatarFileInput');
  if (!avatarInput) {
    avatarInput = document.createElement('input');
    avatarInput.type = 'file';
    avatarInput.id = 'avatarFileInput';
    avatarInput.accept = 'image/*';
    avatarInput.style.display = 'none';
    document.body.appendChild(avatarInput);
  }

  // Store DOM refs
  dom.shell = $('#appShell');
  dom.sidebar = $('#sidebar');
  dom.convoList = $('#convoList');
  dom.mainArea = $('#mainArea');
  dom.chatArea = $('#chatArea');
  dom.noChat = $('#noChat');
  dom.chatHead = $('#chatHead');
  dom.chatHeadTitle = $('#chatHeadTitle');
  dom.chatHeadSub = $('#chatHeadSub');
  dom.msgList = $('#msgList');
  dom.composerArea = $('#composerArea');
  dom.replyBar = $('#replyBar');
  dom.textInput = $('#textInput');
  dom.btnSend = $('#btnSend');
  dom.fileInput = $('#fileInput');
  dom.btnPrivacy = $('#btnPrivacy');
  dom.btnBlock = $('#btnBlock');
  dom.expiryPicker = $('#expiryPicker');

  // Attach static listeners
  attachStaticListeners(avatarInput);

  // Clear force rebuild flag
  window._forceRebuild = false;

  updateSidebar();
  if (activeConvoId) {
    dom.chatArea.style.display = 'flex';
    dom.noChat.style.display = 'none';
    updateChatHead();
    updateMessages();
  } else {
    dom.chatArea.style.display = 'none';
    dom.noChat.style.display = 'flex';
  }
}

// ----- UPDATERS -----
function updateSidebar() {
  const list = dom.convoList;
  if (!list) return;
  const scrollPos = list.scrollTop;
  list.innerHTML = convos.length === 0 ? `
    <div class="empty-side">
      <div style="font-size:13px; color:var(--text); margin-bottom:6px;">No conversations yet</div>
      <div>Start one to begin a sealed exchange.</div>
    </div>
  ` : convos.map(c => {
    const title = convoTitle(c);
    const other = c.type === 'dm' ? getOtherUsername(c) : null;
    const avatar = other ? getUserAvatar(other) : null;
    return `
    <div class="convo ${c.id===activeConvoId?'active':''}" data-id="${c.id}">
      <div class="avatar">${avatar ? `<img src="${avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" />` : escapeHtml(initials(title))}</div>
      <div class="convo-meta">
        <div class="convo-name">${escapeHtml(title)}${c.type==='group'?'<span class="badge">GROUP</span>':''}</div>
        <div class="convo-sub">${escapeHtml(convoSubtitle(c))}</div>
      </div>
    </div>
  `}).join('');
  list.scrollTop = scrollPos;
  list.querySelectorAll('.convo').forEach(el => {
    el.addEventListener('click', async () => {
      activeConvoId = el.dataset.id;
      ui.replyingTo = null;
      await loadMessages(activeConvoId);
      await markRead(activeConvoId);
      dom.chatArea.style.display = 'flex';
      dom.noChat.style.display = 'none';
      updateChatHead();
      updateMessages();
      dom.msgList.scrollTop = dom.msgList.scrollHeight;
    });
  });
}

function updateChatHead() {
  if (!activeConvoId) return;
  const convo = convos.find(c => c.id === activeConvoId);
  if (!convo) return;
  dom.chatHeadTitle.textContent = convoTitle(convo);
  if (convo.type === 'dm') {
    const other = getOtherUsername(convo);
    const entry = directory.find(d => d.username === other);
    const online = entry && isUserOnline(other);
    dom.chatHeadSub.textContent = online ? '🟢 Online' : (entry ? formatLastSeen(entry.lastSeen) : '@' + other);
  } else {
    dom.chatHeadSub.textContent = convo.members.length + ' members';
  }
}

function updateMessages() {
  const msgs = messagesCache[activeConvoId] || [];
  if (!dom.msgList) return;
  const scrollPos = dom.msgList.scrollTop;
  const atBottom = dom.msgList.scrollHeight - scrollPos < 100;

  dom.msgList.innerHTML = msgs.map(m => renderMessage(m)).join('');

  // Attach listeners
  dom.msgList.querySelectorAll('.msg-row').forEach(row => {
    const mid = row.dataset.msgId;
    if (!mid) return;
    // Reaction picker
    const reactionPicker = row.querySelector('.reaction-picker');
    if (reactionPicker) {
      reactionPicker.querySelectorAll('.reaction-emoji').forEach(el => {
        el.addEventListener('click', (e) => {
          e.stopPropagation();
          safely(() => addReaction(mid, el.dataset.emoji), 'Could not add reaction.');
        });
      });
    }
    // Reply button
    const replyBtn = row.querySelector('.reply-btn');
    if (replyBtn) {
      replyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const msg = messagesCache[activeConvoId].find(m => m.id === mid);
        if (!msg) return;
        const preview = msg.type === 'text' ? bufToStr(msg._plainBuf) : '[File/Image]';
        ui.replyingTo = { id: mid, sender: msg.sender, preview };
        renderApp();
        dom.textInput?.focus();
      });
    }
  });

  // Reply preview click to scroll
  dom.msgList.querySelectorAll('.reply-preview').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const targetId = el.dataset.replyId;
      if (targetId) {
        window.location.hash = 'msg-' + targetId;
        scrollToMessage(targetId);
      }
    });
  });

  // Save & download listeners
  dom.msgList.querySelectorAll('[data-save-id]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      safely(() => markSaved(el.dataset.saveId), 'Could not save message.');
    });
  });
  dom.msgList.querySelectorAll('[data-download-id]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      setTimeout(() => safely(() => markSaved(el.dataset.downloadId), 'Could not mark download.'), 300);
    });
  });

  if (atBottom) dom.msgList.scrollTop = dom.msgList.scrollHeight;
}

function renderMessage(m) {
  const mine = m.sender === session.username;
  const senderName = mine ? 'You' : getUserDisplayName(m.sender);
  const avatar = mine ? session.avatar : getUserAvatar(m.sender);
  let body = '';

  let replyHtml = '';
  if (m.replyToId && m.replyToPreview) {
    replyHtml = `
      <div class="reply-preview" data-reply-id="${m.replyToId}" style="cursor:pointer; background:var(--surface-2); border-left: 2px solid var(--teal); padding:4px 8px; border-radius:4px; margin-bottom:6px; font-size:12px; color:var(--muted);">
        <span style="color:var(--teal);">↩️ ${getUserDisplayName(m.replyToPreview.sender || '')}</span>
        <div style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(m.replyToPreview)}</div>
      </div>
    `;
  }

  if (m.type === 'text') {
    body = `<div>${escapeHtml(bufToStr(m._plainBuf))}</div>`;
  } else {
    const blob = new Blob([m._plainBuf], { type: m.mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    if (m.type === 'image') {
      body = `<div><img src="${url}" /></div>`;
    } else {
      body = `<a class="file-chip" href="${url}" download="${escapeHtml(m.filename||'file')}" data-download-id="${m.id}">${fileSvg()} ${escapeHtml(m.filename||'file')}</a>`;
    }
  }

  let reactionsHtml = '';
  if (m.reactions) {
    const emojis = Object.values(m.reactions);
    if (emojis.length > 0) {
      const grouped = emojis.reduce((acc, em) => {
        acc[em] = (acc[em] || 0) + 1;
        return acc;
      }, {});
      reactionsHtml = `<div class="reactions">${Object.entries(grouped).map(([em, count]) => `<span class="reaction-badge">${em} ${count}</span>`).join('')}</div>`;
    }
  }

  const pickerHtml = `<div class="reaction-picker">${['👍','❤️','😂','😮','😢','🙏'].map(e => `<span class="reaction-emoji" data-emoji="${e}">${e}</span>`).join('')}</div>`;
  const replyBtnHtml = `<span class="reply-btn" style="cursor:pointer; font-size:12px; margin-right:8px; opacity:0.6;">↩️</span>`;

  let readStatus = '';
  if (!mine && m.readBy && m.readBy[session.username]) {
    readStatus = '<span style="font-size:10px; color:var(--teal); margin-left:8px;">✓ Seen</span>';
  } else if (!mine) {
    readStatus = '<span style="font-size:10px; color:var(--muted); margin-left:8px;">✓ Delivered</span>';
  }

  let expiryInfo = '';
  if (m.expiresAt) {
    const remaining = Math.max(0, m.expiresAt - Date.now());
    if (remaining > 0) {
      const mins = Math.floor(remaining / 60000);
      const secs = Math.floor((remaining % 60000) / 1000);
      expiryInfo = `<span style="font-size:9px; color:var(--muted); margin-left:6px;">⌛ ${mins}m ${secs}s</span>`;
    }
  }

  const savedMarkup = m.savedAt
    ? `<span class="save-btn saved"><span class="ring"></span> deletes ${timeLeft(m.savedAt)}</span>`
    : `<button class="save-btn" data-save-id="${m.id}">Save</button>`;

  const avatarHtml = avatar ? `<img src="${avatar}" style="width:16px;height:16px;border-radius:50%;object-fit:cover;margin-right:4px;" />` : '';

  return `
    <div class="msg-row ${mine?'mine':'theirs'}" data-msg-id="${m.id}">
      <div class="msg-sender">${avatarHtml} ${escapeHtml(senderName)}</div>
      <div class="bubble">
        ${replyHtml}
        ${body}
        ${pickerHtml}
        <div style="display:flex; align-items:center; margin-top:4px; gap:4px;">
          ${replyBtnHtml}
        </div>
      </div>
      ${reactionsHtml}
      <div class="msg-foot">
        <span class="msg-time">${fmtTime(m.ts)}</span>
        ${expiryInfo}
        ${readStatus}
        ${savedMarkup}
      </div>
    </div>
  `;
}

function timeLeft(savedAt) {
  const rem = AUTO_DELETE_MS - (Date.now() - savedAt);
  const mins = Math.max(0, Math.ceil(rem/60000));
  return 'in ' + mins + 'm';
}

// ---- 13. RENDER ----
function render() {
  captureComposerState();
  syncPrivacyState();
  if (!BACKEND_CONFIGURED) { renderBackendSetup(); return; }
  if (!session.username) { renderAuth(); return; }
  renderApp();
  restoreComposerState();
}

function renderApp() {
  // Build shell if needed (or if force rebuild)
  if (!dom.shell || window._forceRebuild) {
    buildShell();
  } else {
    updateSidebar();
    if (activeConvoId) {
      dom.chatArea.style.display = 'flex';
      dom.noChat.style.display = 'none';
      updateChatHead();
      updateMessages();
      getTypingUsers(activeConvoId).then(users => {
        if (users.length > 0) {
          const names = users.map(u => getUserDisplayName(u)).join(', ');
          dom.chatHeadSub.textContent = names + ' typing...';
        } else {
          updateChatHead();
        }
      });
    } else {
      dom.chatArea.style.display = 'none';
      dom.noChat.style.display = 'flex';
    }
  }

  updateReplyBar();

  if (ui.showNewChat) {
    renderNewChatModal();
  } else {
    const modal = $('#modalBg');
    if (modal) modal.remove();
  }
}

function updateReplyBar() {
  if (!dom.replyBar) return;
  if (ui.replyingTo) {
    dom.replyBar.style.display = 'flex';
    const sender = ui.replyingTo.sender;
    const displayName = sender === session.username ? 'You' : getUserDisplayName(sender);
    const senderEl = $('#replySender');
    const previewEl = $('#replyPreviewText');
    if (senderEl) senderEl.textContent = displayName;
    if (previewEl) previewEl.textContent = ui.replyingTo.preview || '';
  } else {
    dom.replyBar.style.display = 'none';
  }
}

// ---- 14. AUTH SCREENS ----
function renderBackendSetup() {
  root.innerHTML = `<div class="auth-wrap"><div class="auth-card"><div class="term-bar"><div class="term-dot" style="background:#FF5C5C;"></div><div class="term-dot" style="background:#F5C542;"></div><div class="term-dot" style="background:#00FF9C;"></div><div class="term-title">root@sealed:~$ setup</div></div><div class="auth-body"><div class="auth-head"><div class="seal">${sealSvg()}</div><div class="wordmark">Seal<span>ed</span></div></div><div class="boot-log" style="margin-top:14px;"><div style="color:#F5C542;">✗ no database configured</div></div><div class="auth-sub" style="margin-top:16px;">Set FIREBASE_DB_URL in config.js</div></div></div></div>`;
}

function renderAuth() {
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
          ${ui.authTab==='signup' ? `<div class="hint">min. 8 characters recommended.</div>` : ''}
          <div style="margin-top: 12px; display: flex; align-items: center; gap: 8px;">
            <input type="checkbox" id="f-remember" style="accent-color: var(--teal); width: 16px; height: 16px;" ${ui.rememberMe ? 'checked' : ''} />
            <label for="f-remember" style="margin:0; font-size:12px; color:var(--muted); cursor:pointer;">Remember me</label>
          </div>
          <button class="btn" type="submit" ${ui.busy?'disabled':''}>${ui.busy ? 'working...' : (ui.authTab==='login' ? '[ log in ]' : '[ create sealed account ]')}</button>
          <div class="err">${ui.authErr ? escapeHtml(ui.authErr) : ''}</div>
        </form>
        ${ui.busy && ui.authSteps.length ? `<div class="boot-log">${ui.authSteps.map((s,i)=>`<div class="${i<ui.authSteps.length-1?'done':''}">${escapeHtml(s)}${i===ui.authSteps.length-1?' <span class="blink">_</span>':''}</div>`).join('')}</div>` : ''}
        ${ui.authTab==='signup' && !ui.busy ? `<div class="hint">your passphrase unlocks your private key — it's never stored.</div>` : ''}
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
    ui.rememberMe = $('#f-remember').checked;
    
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
      await loadDirectory();
      await loadConvos();
      startPolling();
      ui.busy = false;
      render();
    }catch(err){
      ui.busy = false; ui.authSteps = []; ui.authErr = err.message || 'Something went wrong.'; render();
    }
  });
}

// ---- 15. NEW CHAT MODAL ----
function renderNewChatModal() {
  const others = directory.filter(d => d.username !== session.username);
  let modalHtml = `
    <div class="modal-bg" id="modalBg">
      <div class="modal">
        <div class="modal-body">
          <h3>New private chat</h3>
          <div class="modal-sub">Pick one person for 1:1, or several for a group.</div>
          <input type="text" id="contactSearch" placeholder="Search contacts..." style="width:100%; background:#000; border:1px solid var(--line); color:var(--text); padding:8px 10px; border-radius:4px; margin-bottom:12px;" />
          <div class="user-list" id="userList">
            ${others.length===0 ? `<div class="empty-side">No contacts yet</div>` : ''}
            ${others.map(d => `
              <label class="user-pick" data-username="${escapeHtml(d.username)}">
                <input type="checkbox" value="${escapeHtml(d.username)}" ${ui.picked.includes(d.username)?'checked':''} />
                <div class="avatar">${d.avatar ? `<img src="${d.avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" />` : escapeHtml(initials(d.displayName))}</div>
                <div>
                  <div style="font-size:13.5px;font-weight:600;">${escapeHtml(d.displayName)}</div>
                  <div style="font-size:11px;color:var(--muted);font-family:var(--mono);">@${escapeHtml(d.username)}</div>
                </div>
              </label>
            `).join('')}
          </div>
          ${ui.picked.length > 1 ? `<input type="text" id="groupName" placeholder="Group name" style="width:100%; background:#000; border:1px solid var(--line); color:var(--text); padding:8px 10px; border-radius:4px; margin-bottom:14px;" />` : ''}
          <div class="modal-footer">
            <button class="btn ghost" id="modalCancel" style="flex:1;">Cancel</button>
            <button class="btn" id="modalGo" style="flex:1;" ${ui.picked.length===0?'disabled':''}>${ui.picked.length>1?'Create group':'Start chat'}</button>
          </div>
        </div>
      </div>
    </div>
  `;

  const old = $('#modalBg');
  if (old) old.remove();
  document.body.insertAdjacentHTML('beforeend', modalHtml);

  const searchInput = $('#contactSearch');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase().trim();
      document.querySelectorAll('.user-pick').forEach(el => {
        const name = el.dataset.username.toLowerCase();
        const display = el.querySelector('div div')?.textContent?.toLowerCase() || '';
        el.style.display = (name.includes(q) || display.includes(q)) ? 'flex' : 'none';
      });
    });
  }

  $('#modalBg')?.addEventListener('click', (e) => {
    if (e.target.id === 'modalBg') {
      ui.showNewChat = false;
      render();
    }
  });
  $('#modalCancel')?.addEventListener('click', () => {
    ui.showNewChat = false;
    render();
  });
  document.querySelectorAll('.user-pick input').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) ui.picked.push(cb.value);
      else ui.picked = ui.picked.filter(u => u !== cb.value);
      renderNewChatModal();
    });
  });
  $('#modalGo')?.addEventListener('click', async () => {
    ui.showNewChat = false;
    await safely(async () => {
      if (ui.picked.length === 1) {
        await openOrCreateDM(ui.picked[0]);
      } else if (ui.picked.length > 1) {
        const name = $('#groupName')?.value || '';
        await createGroup(name, ui.picked);
      }
    }, 'Could not start chat.');
    ui.picked = [];
    render();
  });
}

// ---- 16. STATIC LISTENERS ----
function attachStaticListeners(avatarInput) {
  // Logout
  $('#btnLogout')?.addEventListener('click', logOut);
  
  // New Chat
  $('#btnNewChat')?.addEventListener('click', () => {
    ui.showNewChat = true;
    ui.picked = [];
    render();
  });
  
  // Privacy
  $('#btnPrivacy')?.addEventListener('click', () => {
    setPrivacyMode(!ui.privacyMode);
    render();
  });
  
  // Block
  dom.btnBlock?.addEventListener('click', async () => {
    if (!activeConvoId) return toast('No chat selected.');
    const convo = convos.find(c => c.id === activeConvoId);
    if (!convo) return toast('Conversation not found.');
    if (convo.type === 'group') return toast('Block only works in private chats.');
    const other = getOtherUsername(convo);
    if (!other) return;
    const choice = confirm(`Block @${other}?\nOK = Hard Block, Cancel = Soft Block`);
    if (choice === true) await setBlock(other, 'hard');
    else await setBlock(other, 'soft');
  });

  // Avatar upload
  const avatarEditBtn = $('#avatarEditBtn');
  if (avatarEditBtn) {
    avatarEditBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (avatarInput) avatarInput.click();
    });
  }
  if (avatarInput) {
    avatarInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async (ev) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          const size = 128;
          canvas.width = size;
          canvas.height = size;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, size, size);
          const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
          safely(() => updateAvatar(dataUrl), 'Could not update avatar.');
        };
        img.src = ev.target.result;
      };
      reader.readAsDataURL(file);
      avatarInput.value = '';
    });
  }

  // Send button
  dom.btnSend?.addEventListener('click', doSendText);
  
  // File input
  dom.fileInput?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    await safely(async () => {
      await sendMessage({type, file});
    }, 'Could not send file.');
    dom.fileInput.value = '';
  });

  // Text input
  if (dom.textInput) {
    dom.textInput.addEventListener('input', () => {
      ui.composerText = dom.textInput.value;
      ui.composerSelectionStart = dom.textInput.selectionStart ?? dom.textInput.value.length;
      ui.composerSelectionEnd = dom.textInput.selectionEnd ?? dom.textInput.value.length;
      debounceTyping();
      dom.textInput.style.height = 'auto';
      dom.textInput.style.height = Math.min(dom.textInput.scrollHeight, 120) + 'px';
    });
    dom.textInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        doSendText();
      }
      if (e.key === 'Escape' && ui.replyingTo) {
        ui.replyingTo = null;
        renderApp();
      }
    });
    dom.textInput.addEventListener('focus', () => { ui.composerFocused = true; });
    dom.textInput.addEventListener('blur', () => { ui.composerFocused = false; });
  }

  // Cancel Reply
  const cancelReply = $('#cancelReplyBtn');
  if (cancelReply) {
    cancelReply.addEventListener('click', () => {
      ui.replyingTo = null;
      renderApp();
      dom.textInput?.focus();
    });
  }

  // Expiry picker
  if (dom.expiryPicker) {
    dom.expiryPicker.addEventListener('change', () => {
      const val = dom.expiryPicker.value;
      ui.messageExpiry = val ? parseInt(val) : null;
    });
  }

  // Window events
  window.addEventListener('blur', handleWindowBlur);
  window.addEventListener('focus', handleWindowFocus);
  window.addEventListener('beforeunload', () => {
    if (session.username) updateLastSeen();
  });
}

// ---- 17. SEND HELPER ----
async function doSendText() {
  const text = dom.textInput?.value;
  if (!text || !text.trim()) return;
  dom.textInput.value = '';
  ui.composerText = '';
  dom.textInput.style.height = 'auto';
  await safely(async () => {
    await sendMessage({type: 'text', text});
  }, 'Message did not send.');
  dom.msgList.scrollTop = dom.msgList.scrollHeight;
}

// ---- 18. SVG HELPERS (Fixed) ----
function sealSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-4z" fill="#0B0D12" opacity="0.85"/><path d="M8.5 12.2l2.4 2.4 4.6-4.9" stroke="#E8A33D" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}
function logoutSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>`; }
function clipSvg(){ return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a5 5 0 01-7.07-7.07l9.19-9.19a3.5 3.5 0 014.95 4.95L9.41 17.86a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>`; }
function sendSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0B0D12" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>`; }
function fileSvg(){ return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>`; }

// ---- 19. AUTO-LOGIN EXECUTION ----
(async function runAutoLogin() {
  if (window._autoLoginData) {
    const { username, password } = window._autoLoginData;
    try {
      ui.busy = true;
      renderAuth();
      await logIn(username, password);
      await loadDirectory();
      await loadConvos();
      startPolling();
      ui.busy = false;
      render();
    } catch (e) {
      console.warn('Auto-login failed:', e);
      localStorage.removeItem('sealed_creds');
      ui.busy = false;
      render();
    }
    delete window._autoLoginData;
  }
})();

// ---- 20. START ----
render();
console.log('✅ Sealed v2.0 ready');