const state = {
  session: { username: null, displayName: null, privateKey: null, publicKeyJwk: null, fingerprint: null },
  directory: [],
  convos: [],
  activeConvoId: null,
  messagesCache: {},
  pollTimer: null,
  pendingUploads: [],
  objectUrls: [],
  blocks: [],
  scheduled: [],
  readTracked: new Set(),
  ui: {
    authTab: 'login',
    authErr: '',
    busy: false,
    authSteps: [],
    showNewChat: false,
    picked: [],
    online: navigator.onLine,
    privacyMode: false,
    search: '',
    messageSearch: '',
    showEmoji: false,
    uploadProgress: 0,
    showProfile: false,
    showSchedule: false,
    profileDraft: { displayName: '', bio: '', avatar: '', retentionDays: 30 },
    scheduleDraft: { text: '', when: '' },
    voiceStatus: 'idle',
    voiceText: ''
  }
};

const root = document.getElementById('root');

function toast(msg){
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2600);
}

function setOnlineStatus(online){
  state.ui.online = online;
  const pill = document.getElementById('connStatus');
  if (pill){
    pill.textContent = online ? 'online' : 'offline';
    pill.className = 'status-pill ' + (online ? 'online' : 'offline');
  }
}

function persistSessionState(){
  if (!state.session.username){
    sessionStorage.removeItem('sealed-session');
    return;
  }
  sessionStorage.setItem('sealed-session', JSON.stringify({
    username: state.session.username,
    displayName: state.session.displayName,
    publicKeyJwk: state.session.publicKeyJwk,
    fingerprint: state.session.fingerprint
  }));
}

async function restoreSessionState(){
  try{
    const sessionState = JSON.parse(sessionStorage.getItem('sealed-session') || 'null');
    if (!sessionState) return false;
    state.session = { ...state.session, ...sessionState, privateKey: null };
    return false;
  } catch (e) {
    sessionStorage.removeItem('sealed-session');
    return false;
  }
}

async function loadDirectory(){
  const data = await FirebaseStore.getJSON('directory');
  state.directory = Array.isArray(data) ? data : [];
}

async function loadBlocks(){
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  state.blocks = Array.isArray(account?.blocks) ? account.blocks : [];
}

async function saveAccountMeta(patch){
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  const next = { ...(account || {}), ...patch };
  await FirebaseStore.setJSON('account:' + state.session.username, next);
  return next;
}

async function updateLastActive(){
  if (!state.session.username) return;
  await saveAccountMeta({ lastSeenAt: Date.now() });
}

async function maybeExpireAccount(account){
  if (!account || !state.session.username) return;
  const expiryMs = 3 * 24 * 60 * 60 * 1000;
  if (!account.lastSeenAt) return;
  if (Date.now() - account.lastSeenAt > expiryMs){
    await deleteCurrentAccount();
    throw new Error('This account expired because it was inactive for 3 days.');
  }
}

async function deleteCurrentAccount(){
  if (!state.session.username) return;
  const username = state.session.username;
  await FirebaseStore.deleteJSON('account:' + username);
  await FirebaseStore.deleteJSON('directory');
  await FirebaseStore.deleteJSON('userConvos:' + username);
  const directory = state.directory.filter(entry => entry.username !== username);
  await FirebaseStore.setJSON('directory', directory);
  sessionStorage.removeItem('sealed-session');
  state.session = { username: null, displayName: null, privateKey: null, publicKeyJwk: null, fingerprint: null };
  state.directory = [];
  state.convos = [];
  state.messagesCache = {};
  render();
}

async function signUp(username, displayName, password, onStep){
  username = sanitizeUsername(username);
  displayName = normalizeDisplayName(displayName) || username;
  if (!username || !password) throw new Error('Username and password are required.');
  if (password.length < 8) throw new Error('Use a password of at least 8 characters.');
  if (!/^(?=.*[A-Za-z])(?=.*\d).+/.test(password)) throw new Error('Use a stronger passphrase with letters and numbers.');

  onStep?.('checking username availability');
  await loadDirectory();
  if (state.directory.some(entry => entry.username === username)) throw new Error('That username is already taken.');

  const existing = await FirebaseStore.getJSON('account:' + username);
  if (existing) throw new Error('That username is already taken.');

  onStep?.('generating RSA-2048 keypair');
  const keypair = await CryptoStore.generateKeypair();
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);

  onStep?.('deriving key from passphrase (PBKDF2, 250000 rounds)');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapKey = await CryptoStore.deriveWrapKey(password, salt);

  onStep?.('sealing private key with AES-256-GCM');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encPrivate = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, strToBuf(JSON.stringify(privateKeyJwk)));

  const accountPayload = {
    username,
    displayName,
    publicKeyJwk,
    salt: buf2b64(salt),
    iv: buf2b64(iv),
    encPrivateKey: buf2b64(encPrivate),
    createdAt: Date.now(),
    lastSeenAt: Date.now(),
    retentionDays: 30,
    profile: { displayName, bio: '', avatar: '', joinDate: Date.now(), lastActiveAt: Date.now() },
    blocks: []
  };

  onStep?.('writing account record');
  await FirebaseStore.setJSON('account:' + username, accountPayload);

  onStep?.('computing key fingerprint');
  const fingerprint = await CryptoStore.fingerprintOf(publicKeyJwk);
  const directoryEntry = { username, displayName, publicKeyJwk, fingerprint, bio: '' };
  state.directory.push(directoryEntry);
  await FirebaseStore.setJSON('directory', state.directory);

  onStep?.('done');
  state.session = { username, displayName, privateKey: keypair.privateKey, publicKeyJwk, fingerprint };
  persistSessionState();
  await FirebaseStore.setJSON('userConvos:' + username, []);
}

async function logIn(username, password){
  username = sanitizeUsername(username);
  const account = await FirebaseStore.getJSON('account:' + username);
  if (!account) throw new Error('No account with that username.');
  await maybeExpireAccount(account);

  const wrapKey = await CryptoStore.deriveWrapKey(password, new Uint8Array(b642buf(account.salt)));
  try{
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b642buf(account.iv)) }, wrapKey, b642buf(account.encPrivateKey));
    const privateKeyJwk = JSON.parse(bufToStr(plain));
    const privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
    const fingerprint = await CryptoStore.fingerprintOf(account.publicKeyJwk);
    state.session = { username, displayName: account.displayName, privateKey, publicKeyJwk: account.publicKeyJwk, fingerprint };
    persistSessionState();
    await saveAccountMeta({ lastSeenAt: Date.now(), displayName: account.displayName, profile: account.profile || { displayName: account.displayName, bio: '', avatar: '', joinDate: account.createdAt || Date.now(), lastActiveAt: Date.now() } });
  } catch (e) {
    throw new Error('Wrong password.');
  }
}

function revokeObjectUrls(){
  state.objectUrls.forEach(url => URL.revokeObjectURL(url));
  state.objectUrls = [];
}

function logOut(){
  state.session = { username: null, displayName: null, privateKey: null, publicKeyJwk: null, fingerprint: null };
  state.convos = []; state.messagesCache = {}; state.activeConvoId = null; state.blocks = []; state.scheduled = [];
  if (state.pollTimer) clearInterval(state.pollTimer);
  sessionStorage.removeItem('sealed-session');
  revokeObjectUrls();
  render();
}

function sortConvos(list){
  return [...list].sort((a, b) => {
    if ((a.pinned || 0) !== (b.pinned || 0)) return (b.pinned || 0) - (a.pinned || 0);
    return (b.lastActivity || b.createdAt || 0) - (a.lastActivity || a.createdAt || 0);
  });
}

async function loadConvos(){
  const ids = (await FirebaseStore.getJSON('userConvos:' + state.session.username)) || [];
  const list = [];
  for (const id of ids){
    const convo = await FirebaseStore.getJSON('convo:' + id);
    if (convo) list.push(convo);
  }
  state.convos = sortConvos(list.filter(convo => !convo.archived));
  state.archivedConvos = sortConvos(list.filter(convo => convo.archived));
}

async function addConvoToUser(username, convoId){
  const list = (await FirebaseStore.getJSON('userConvos:' + username)) || [];
  if (!list.includes(convoId)){
    list.push(convoId);
    await FirebaseStore.setJSON('userConvos:' + username, list);
  }
}

function dmId(a, b){ return 'dm_' + [a, b].sort().join('__'); }

async function openOrCreateDM(otherUsername){
  const id = dmId(state.session.username, otherUsername);
  let convo = await FirebaseStore.getJSON('convo:' + id);
  if (!convo){
    convo = { id, type: 'dm', members: [state.session.username, otherUsername], createdAt: Date.now(), lastActivity: Date.now(), pinned: false, archived: false };
    await FirebaseStore.setJSON('convo:' + id, convo);
    await FirebaseStore.setJSON('messages:' + id, []);
    await addConvoToUser(state.session.username, id);
    await addConvoToUser(otherUsername, id);
  }
  await loadConvos();
  state.activeConvoId = id;
  await loadMessages(id);
  render();
}

async function createGroup(name, memberUsernames){
  const id = 'grp_' + randomId();
  const members = Array.from(new Set([state.session.username, ...memberUsernames]));
  const convo = { id, type: 'group', name: name || 'Untitled group', members, createdAt: Date.now(), lastActivity: Date.now(), pinned: false, archived: false };
  await FirebaseStore.setJSON('convo:' + id, convo);
  await FirebaseStore.setJSON('messages:' + id, []);
  for (const member of members) await addConvoToUser(member, id);
  await loadConvos();
  state.activeConvoId = id;
  await loadMessages(id);
  render();
}

async function loadMessages(convoId){
  let list = (await FirebaseStore.getJSON('messages:' + convoId)) || [];
  const now = Date.now();
  const before = list.length;
  const retentionDays = Number((await FirebaseStore.getJSON('account:' + state.session.username))?.retentionDays || 30);
  const cutoff = now - retentionDays * 24 * 60 * 60 * 1000;
  list = list.filter(message => !(message.expiresAt && message.expiresAt < now) && (!message.savedAt || (now - message.savedAt) <= APP_CONFIG.AUTO_DELETE_MS));
  list = list.filter(message => !message.deleted);
  if (list.length !== before) await FirebaseStore.setJSON('messages:' + convoId, list);

  const decrypted = [];
  for (const message of list){
    try{
      const plainBuf = await CryptoStore.decryptMessage(message);
      decrypted.push({ ...message, _plainBuf: plainBuf });
    } catch (e) {
      logDebug('Skipping unreadable message', e.message);
    }
  }
  state.messagesCache[convoId] = decrypted;
  if (convoId === state.activeConvoId){
    for (const message of decrypted){
      if (message.sender !== state.session.username){
        await maybeMarkMessageRead(convoId, message);
      }
    }
  }
}

async function maybeMarkMessageRead(convoId, message){
  const key = `${convoId}:${message.id}`;
  if (state.readTracked.has(key) || message.sender === state.session.username) return;
  state.readTracked.add(key);
  const list = (await FirebaseStore.getJSON('messages:' + convoId)) || [];
  const current = list.find(entry => entry.id === message.id);
  if (!current) return;
  if (!current.readBy) current.readBy = {};
  if (!current.readBy[state.session.username]){
    current.readBy[state.session.username] = Date.now();
    await FirebaseStore.setJSON('messages:' + convoId, list);
  }
}

async function queuePendingMessage(messagePayload){
  state.pendingUploads.push(messagePayload);
  if (navigator.onLine) await flushPendingMessages();
}

async function flushPendingMessages(){
  if (!navigator.onLine || state.pendingUploads.length === 0) return;
  const pending = [...state.pendingUploads];
  state.pendingUploads = [];
  for (const payload of pending){
    try{ await FirebaseStore.setJSON('messages:' + payload.convoId, payload.data); } catch (e) { state.pendingUploads.push(payload); }
  }
}

async function sendMessage({ type, text, file, replyTo }){
  const convo = state.convos.find(c => c.id === state.activeConvoId) || state.archivedConvos?.find(c => c.id === state.activeConvoId);
  if (!convo) return;

  const blockState = await FirebaseStore.getJSON('block:' + convo.id);
  if (blockState?.active && blockState.locked) {
    toast('Communication is paused until the conversation is unblocked.');
    return;
  }

  if (blockState?.active && !blockState.finalMessagesUsed?.[state.session.username] && (type === 'text' && String(text || '').trim().length > 200)){
    toast('Final messages are limited to 200 characters.');
    return;
  }

  let bytes; let filename = null; let mime = null;
  if (type === 'text'){
    const value = String(text || '').trim();
    if (!value) return;
    bytes = strToBuf(value);
  } else {
    filename = file.name; mime = file.type; bytes = await file.arrayBuffer();
    if (bytes.byteLength > APP_CONFIG.MAX_FILE_SIZE_BYTES){ toast('That file is a bit large for encrypted storage — keep it under ~3MB.'); return; }
  }

  const enc = await CryptoStore.encryptForRecipients(new Uint8Array(bytes), convo.members);
  const msg = {
    id: randomId(),
    sender: state.session.username,
    ts: Date.now(),
    type,
    filename,
    mime,
    iv: enc.iv,
    ciphertext: enc.ciphertext,
    keys: enc.keys,
    savedAt: null,
    status: 'sent',
    replyTo: replyTo || null,
    expiresAt: Date.now() + ((await FirebaseStore.getJSON('account:' + state.session.username))?.retentionDays || 30) * 24 * 60 * 60 * 1000,
    readBy: {}
  };

  if (blockState?.active){
    const used = blockState.finalMessagesUsed || {};
    used[state.session.username] = { text: String(text || '').slice(0, 200), ts: Date.now() };
    blockState.finalMessagesUsed = used;
    blockState.locked = Object.keys(used).length >= 2;
    await FirebaseStore.setJSON('block:' + convo.id, blockState);
  }

  const list = (await FirebaseStore.getJSON('messages:' + convo.id)) || [];
  list.push(msg);
  await FirebaseStore.setJSON('messages:' + convo.id, list);
  convo.lastActivity = Date.now();
  await FirebaseStore.setJSON('convo:' + convo.id, convo);
  await loadMessages(convo.id);
  await loadConvos();
  render();
  flashSeal();
  await updateLastActive();
}

async function markSaved(msgId){
  const list = (await FirebaseStore.getJSON('messages:' + state.activeConvoId)) || [];
  const message = list.find(entry => entry.id === msgId);
  if (message && !message.savedAt){
    message.savedAt = Date.now();
    await FirebaseStore.setJSON('messages:' + state.activeConvoId, list);
    await loadMessages(state.activeConvoId);
    render();
  }
}

async function deleteMessage(messageId){
  const list = (await FirebaseStore.getJSON('messages:' + state.activeConvoId)) || [];
  const index = list.findIndex(entry => entry.id === messageId);
  if (index >= 0){
    list[index].deleted = true;
    await FirebaseStore.setJSON('messages:' + state.activeConvoId, list);
    await loadMessages(state.activeConvoId);
    render();
  }
}

async function editMessage(messageId){
  const list = (await FirebaseStore.getJSON('messages:' + state.activeConvoId)) || [];
  const message = list.find(entry => entry.id === messageId);
  if (!message || message.sender !== state.session.username) return;
  const nextText = window.prompt('Edit message', bufToStr(message._plainBuf || strToBuf('')));
  if (!nextText) return;
  const bytes = strToBuf(nextText);
  const enc = await CryptoStore.encryptForRecipients(new Uint8Array(bytes), (await FirebaseStore.getJSON('convo:' + state.activeConvoId)).members);
  message.iv = enc.iv; message.ciphertext = enc.ciphertext; message.keys = enc.keys; message.editedAt = Date.now();
  await FirebaseStore.setJSON('messages:' + state.activeConvoId, list);
  await loadMessages(state.activeConvoId);
  render();
}

async function forwardMessage(messageId){
  const convo = state.convos.find(c => c.id === state.activeConvoId);
  const list = (await FirebaseStore.getJSON('messages:' + state.activeConvoId)) || [];
  const message = list.find(entry => entry.id === messageId);
  if (!message || !convo) return;
  const targetId = window.prompt('Forward to conversation ID', convo.id);
  if (!targetId) return;
  const targetConvo = state.convos.find(c => c.id === targetId) || state.archivedConvos?.find(c => c.id === targetId);
  if (!targetConvo) return;
  const bytes = await CryptoStore.decryptMessage(message);
  const enc = await CryptoStore.encryptForRecipients(new Uint8Array(bytes), targetConvo.members);
  const forwarded = { id: randomId(), sender: state.session.username, ts: Date.now(), type: message.type, filename: message.filename, mime: message.mime, iv: enc.iv, ciphertext: enc.ciphertext, keys: enc.keys, savedAt: null, status: 'sent', replyTo: message.id, expiresAt: Date.now() + ((await FirebaseStore.getJSON('account:' + state.session.username))?.retentionDays || 30) * 24 * 60 * 60 * 1000 };
  const targetMessages = (await FirebaseStore.getJSON('messages:' + targetConvo.id)) || [];
  targetMessages.push(forwarded);
  await FirebaseStore.setJSON('messages:' + targetConvo.id, targetMessages);
  toast('Message forwarded.');
}

async function togglePin(convoId){
  const convo = state.convos.find(c => c.id === convoId) || state.archivedConvos?.find(c => c.id === convoId);
  if (!convo) return;
  convo.pinned = !convo.pinned;
  await FirebaseStore.setJSON('convo:' + convo.id, convo);
  await loadConvos();
  render();
}

async function toggleArchive(convoId){
  const convo = state.convos.find(c => c.id === convoId) || state.archivedConvos?.find(c => c.id === convoId);
  if (!convo) return;
  convo.archived = !convo.archived;
  await FirebaseStore.setJSON('convo:' + convo.id, convo);
  await loadConvos();
  render();
}

async function toggleBlockUser(otherUsername){
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  const blocks = new Set(account?.blocks || []);
  if (blocks.has(otherUsername)) blocks.delete(otherUsername); else blocks.add(otherUsername);
  const nextAccount = { ...(account || {}), blocks: Array.from(blocks) };
  await FirebaseStore.setJSON('account:' + state.session.username, nextAccount);
  state.blocks = Array.from(blocks);
  const convo = state.convos.find(c => c.type === 'dm' && c.members.includes(otherUsername));
  if (convo){
    const blockState = { convoId: convo.id, active: true, locked: false, finalMessagesUsed: {} };
    await FirebaseStore.setJSON('block:' + convo.id, blockState);
  }
  toast(blocks.has(otherUsername) ? 'User blocked.' : 'User unblocked.');
  render();
}

async function saveProfile(){
  const draft = state.ui.profileDraft;
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  const next = {
    ...(account || {}),
    displayName: draft.displayName || state.session.displayName,
    retentionDays: Number(draft.retentionDays || account?.retentionDays || 30),
    profile: {
      displayName: draft.displayName || state.session.displayName,
      bio: draft.bio || '',
      avatar: draft.avatar || account?.profile?.avatar || '',
      joinDate: account?.profile?.joinDate || account?.createdAt || Date.now(),
      lastActiveAt: Date.now()
    }
  };
  await FirebaseStore.setJSON('account:' + state.session.username, next);
  state.session.displayName = next.displayName;
  persistSessionState();
  await loadDirectory();
  await loadConvos();
  state.ui.showProfile = false;
  render();
  toast('Profile updated.');
}

async function loadScheduled(){
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  const retentionDays = Number(account?.retentionDays || 30);
  const list = [];
  const rootKey = 'scheduled:' + state.session.username;
  const raw = await FirebaseStore.getJSON(rootKey);
  if (Array.isArray(raw)){
    for (const entry of raw){
      if (entry.targetAt > Date.now()) list.push(entry);
    }
  }
  state.scheduled = list;
  if (state.scheduled.some(entry => entry.targetAt <= Date.now())) await processScheduledMessages();
  return state.scheduled;
}

async function scheduleMessage(text){
  const convo = state.convos.find(c => c.id === state.activeConvoId) || state.archivedConvos?.find(c => c.id === state.activeConvoId);
  if (!convo) return;
  const at = new Date(state.ui.scheduleDraft.when || Date.now() + 60_000).getTime();
  const bytes = strToBuf(String(text || '').trim());
  const enc = await CryptoStore.encryptForRecipients(new Uint8Array(bytes), convo.members);
  const payload = { id: randomId(), sender: state.session.username, ts: Date.now(), type: 'text', iv: enc.iv, ciphertext: enc.ciphertext, keys: enc.keys, savedAt: null, status: 'scheduled', expiresAt: Date.now() + ((await FirebaseStore.getJSON('account:' + state.session.username))?.retentionDays || 30) * 24 * 60 * 60 * 1000 };
  const rootKey = 'scheduled:' + state.session.username;
  const current = (await FirebaseStore.getJSON(rootKey)) || [];
  current.push({ id: randomId(), convoId: convo.id, targetAt: at, payload, createdAt: Date.now() });
  await FirebaseStore.setJSON(rootKey, current);
  state.ui.showSchedule = false;
  await loadScheduled();
  render();
  toast('Message scheduled.');
}

async function processScheduledMessages(){
  const rootKey = 'scheduled:' + state.session.username;
  const current = (await FirebaseStore.getJSON(rootKey)) || [];
  const pending = current.filter(entry => entry.targetAt <= Date.now());
  const remaining = current.filter(entry => entry.targetAt > Date.now());
  for (const entry of pending){
    const convo = state.convos.find(c => c.id === entry.convoId) || state.archivedConvos?.find(c => c.id === entry.convoId);
    if (convo){
      const list = (await FirebaseStore.getJSON('messages:' + convo.id)) || [];
      list.push(entry.payload);
      await FirebaseStore.setJSON('messages:' + convo.id, list);
      convo.lastActivity = Date.now();
      await FirebaseStore.setJSON('convo:' + convo.id, convo);
    }
  }
  await FirebaseStore.setJSON(rootKey, remaining);
  await loadScheduled();
  if (state.activeConvoId) await loadMessages(state.activeConvoId);
  render();
}

async function cancelScheduled(id){
  const rootKey = 'scheduled:' + state.session.username;
  const current = (await FirebaseStore.getJSON(rootKey)) || [];
  const next = current.filter(entry => entry.id !== id);
  await FirebaseStore.setJSON(rootKey, next);
  await loadScheduled();
  render();
}

async function saveRetention(days){
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  const next = { ...(account || {}), retentionDays: Number(days) };
  await FirebaseStore.setJSON('account:' + state.session.username, next);
  toast('Retention updated.');
  render();
}

async function setPrivacyMode(enabled){
  state.ui.privacyMode = enabled;
  document.body.classList.toggle('privacy-on', enabled);
  document.body.classList.toggle('select-none', enabled);
  const account = await FirebaseStore.getJSON('account:' + state.session.username);
  const next = { ...(account || {}), privacyMode: enabled };
  await FirebaseStore.setJSON('account:' + state.session.username, next);
  render();
}

function applyVisibility(){
  if (state.ui.privacyMode && document.hidden){
    document.body.classList.add('privacy-blur');
  } else {
    document.body.classList.remove('privacy-blur');
  }
}

function flashSeal(){
  const el = document.querySelector('.chat-head .seal');
  if (el){ el.classList.remove('stamp'); void el.offsetWidth; el.classList.add('stamp'); }
}

function startPolling(){
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    if (!state.session.username) return;
    try{
      await loadConvos();
      await loadScheduled();
      if (state.activeConvoId) await loadMessages(state.activeConvoId);
      if (navigator.onLine) await flushPendingMessages();
      render();
    } catch (e) {
      logDebug('polling failed', e.message);
    }
  }, APP_CONFIG.POLL_INTERVAL_MS);
}

function render(){
  if (!state.session.username || !state.session.privateKey){
    revokeObjectUrls();
    renderAuth();
    return;
  }
  renderApp();
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
            <div class="tab ${state.ui.authTab === 'login' ? 'active' : ''}" data-tab="login">login</div>
            <div class="tab ${state.ui.authTab === 'signup' ? 'active' : ''}" data-tab="signup">create_account</div>
          </div>
          <form id="authForm">
            <label>username</label>
            <input type="text" id="f-username" autocomplete="username" placeholder="e.g. rayed446" />
            ${state.ui.authTab === 'signup' ? '<label>display_name</label><input type="text" id="f-display" placeholder="what people will see" />' : ''}
            <label>passphrase</label>
            <input type="password" id="f-password" autocomplete="${state.ui.authTab === 'signup' ? 'new-password' : 'current-password'}" placeholder="••••••••" />
            ${state.ui.authTab === 'signup' ? '<div class="hint">min. 8 characters recommended — use letters and numbers for a stronger passphrase.</div>' : ''}
            <button class="btn" type="submit" ${state.ui.busy ? 'disabled' : ''}>${state.ui.busy ? 'working...' : (state.ui.authTab === 'login' ? '[ log in ]' : '[ create sealed account ]')}</button>
            <div class="err">${state.ui.authErr ? escapeHtml(state.ui.authErr) : ''}</div>
          </form>
          ${state.ui.busy && state.ui.authSteps.length ? `<div class="boot-log">${state.ui.authSteps.map((step, index) => `<div class="${index < state.ui.authSteps.length - 1 ? 'done' : ''}">${escapeHtml(step)}${index === state.ui.authSteps.length - 1 ? ' <span class="blink">_</span>' : ''}</div>`).join('')}</div>` : ''}
        </div>
      </div>
    </div>
  `;

  root.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => { state.ui.authTab = tab.dataset.tab; state.ui.authErr = ''; render(); }));
  document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('f-username').value;
    const password = document.getElementById('f-password').value;
    const display = state.ui.authTab === 'signup' ? document.getElementById('f-display').value : '';
    state.ui.authErr = ''; state.ui.busy = true; state.ui.authSteps = ['initializing']; render();
    try{
      if (state.ui.authTab === 'signup'){ await signUp(username, display, password, step => { state.ui.authSteps.push(step); render(); }); }
      else { state.ui.authSteps.push('deriving key from passphrase'); render(); await logIn(username, password); state.ui.authSteps.push('done'); }
      await loadDirectory();
      await loadBlocks();
      await loadConvos();
      await loadScheduled();
      await updateLastActive();
      startPolling();
      state.ui.busy = false;
      render();
    } catch (err) {
      state.ui.busy = false; state.ui.authSteps = []; state.ui.authErr = err.message || 'Something went wrong.'; render();
    }
  });
}

function convoTitle(convo){
  if (convo.type === 'group') return convo.name;
  const other = convo.members.find(m => m !== state.session.username);
  const found = state.directory.find(entry => entry.username === other);
  return found ? found.displayName : other;
}

function convoSubtitle(convo){
  if (convo.type === 'group') return convo.members.length + ' members';
  const other = convo.members.find(m => m !== state.session.username);
  return '@' + other;
}

function unreadCount(convoId){
  const msgs = state.messagesCache[convoId] || [];
  const lastSeen = state.session.lastSeenAt || 0;
  return msgs.filter(message => message.sender !== state.session.username && message.ts > lastSeen).length;
}

function getMessageStatus(message){
  if (message.status === 'scheduled') return 'Scheduled';
  if (message.sender !== state.session.username) return 'Sent';
  if (message.readBy && Object.keys(message.readBy).some(user => user !== state.session.username)) return '✓✓ Read';
  return '✓ Sent';
}

function getSeenAt(message){
  const other = Object.entries(message.readBy || {}).find(([user]) => user !== state.session.username);
  return other ? fmtTime(other[1]) : '';
}

function renderApp(){
  revokeObjectUrls();
  const activeConvo = state.convos.find(c => c.id === state.activeConvoId) || state.archivedConvos?.find(c => c.id === state.activeConvoId);
  root.innerHTML = `
    <div class="shell">
      <div class="sidebar">
        <div class="sb-head">
          <div class="me">
            <div class="avatar">${escapeHtml(initials(state.session.displayName))}</div>
            <div class="me-name">${escapeHtml(state.session.displayName)}</div>
          </div>
          <div class="head-tools">
            <button class="icon-btn" id="btnProfile" aria-label="Open profile">${profileSvg()}</button>
            <button class="icon-btn" id="btnPrivacy" aria-label="Privacy mode">${shieldSvg()}</button>
            <button class="icon-btn" id="btnLogout" aria-label="Log out">${logoutSvg()}</button>
          </div>
        </div>
        <div class="search-box">
          <input id="searchConvos" placeholder="Search users or chats" value="${escapeHtml(state.ui.search)}" />
        </div>
        <div class="sb-actions">
          <button class="btn" id="btnNewChat">New private chat</button>
        </div>
        <div class="convo-list">
          ${(state.convos || []).filter(convo => convoTitle(convo).toLowerCase().includes(state.ui.search.toLowerCase()) || convoSubtitle(convo).toLowerCase().includes(state.ui.search.toLowerCase())).map(convo => `
            <div class="convo ${convo.id === state.activeConvoId ? 'active' : ''}" data-id="${convo.id}">
              <div class="avatar">${escapeHtml(initials(convoTitle(convo)))}</div>
              <div class="convo-meta">
                <div class="convo-name">${escapeHtml(convoTitle(convo))}${convo.type === 'group' ? '<span class="badge">GROUP</span>' : ''}</div>
                <div class="convo-sub">${escapeHtml(convoSubtitle(convo))}</div>
              </div>
              ${unreadCount(convo.id) ? `<span class="counter">${unreadCount(convo.id)}</span>` : ''}
              <button class="mini-btn" data-pin-id="${convo.id}">${convo.pinned ? '★' : '☆'}</button>
            </div>
          `).join('')}
        </div>
      </div>
      <div class="main">
        ${activeConvo ? renderChat(activeConvo) : `<div class="no-chat"><div class="seal">${sealSvg()}</div><div>Pick a conversation, or start a new one.</div></div>`}
      </div>
    </div>
    ${state.ui.showNewChat ? renderNewChatModal() : ''}
    ${state.ui.showProfile ? renderProfileModal() : ''}
    ${state.ui.showSchedule ? renderScheduleModal() : ''}
  `;
  attachAppListeners();
}

function renderChat(convo){
  const msgs = state.messagesCache[convo.id] || [];
  const visible = msgs.filter(message => {
    const query = state.ui.messageSearch.trim().toLowerCase();
    if (!query) return true;
    const text = message.type === 'text' ? bufToStr(message._plainBuf || strToBuf('')) : (message.filename || '');
    return text.toLowerCase().includes(query);
  });
  let headSub;
  if (convo.type === 'dm'){ const other = convo.members.find(m => m !== state.session.username); const found = state.directory.find(entry => entry.username === other); headSub = 'Safety code: ' + (found ? found.fingerprint : ''); }
  else { headSub = convo.members.length + ' members · each message sealed individually per member'; }

  return `
    <div class="chat-head">
      <div>
        <div class="chat-head-title">${escapeHtml(convoTitle(convo))}</div>
        <div class="chat-head-sub">${escapeHtml(headSub)}</div>
        <div id="connStatus" class="status-pill ${state.ui.online ? 'online' : 'offline'}">${state.ui.online ? 'online' : 'offline'}</div>
      </div>
      <div class="chat-head-tools">
        <input id="messageSearch" placeholder="Search messages" value="${escapeHtml(state.ui.messageSearch)}" />
        <button class="icon-btn" data-archive-id="${convo.id}" aria-label="Archive conversation">${archiveSvg()}</button>
        <button class="icon-btn" data-block-id="${convo.id}" aria-label="Block user">${blockSvg()}</button>
        <div class="seal" title="Encrypted with RSA-OAEP + AES-256-GCM">${sealSvg()}</div>
      </div>
    </div>
    <div class="messages" id="msgList">${visible.map(message => renderMessage(message)).join('')}</div>
    <div class="composer">
      <div class="composer-row">
        <label class="icon-btn" style="cursor:pointer;" aria-label="Attach file">${clipSvg()}<input type="file" id="fileInput" style="display:none" /></label>
        <button class="icon-btn" id="btnMic" aria-label="Voice to text">${micSvg()}</button>
        <button class="icon-btn" id="btnEmoji" aria-label="Emoji picker">${emojiSvg()}</button>
        <button class="icon-btn" id="btnSchedule" aria-label="Schedule message">${clockSvg()}</button>
        <textarea id="textInput" rows="1" placeholder="Write a sealed message…"></textarea>
        <button class="send-btn" id="btnSend">${sendSvg()}</button>
      </div>
      ${state.ui.voiceStatus !== 'idle' ? `<div class="voice-status">${escapeHtml(state.ui.voiceStatus)}</div>` : ''}
      ${state.ui.voiceText ? `<div class="voice-preview"><textarea id="voiceTextEdit">${escapeHtml(state.ui.voiceText)}</textarea><button class="btn small" id="btnVoiceSend">Send edited text</button></div>` : ''}
      ${state.ui.showEmoji ? `<div class="emoji-panel">${['😊','😂','❤️','👍','🙏','🔥','🎉','✨','🤝','💬'].map(emoji => `<button class="emoji-btn" data-emoji="${emoji}">${emoji}</button>`).join('')}</div>` : ''}
      ${state.scheduled.length ? `<div class="scheduled-list">${state.scheduled.map(entry => `<div class="scheduled-item">${escapeHtml(convoTitle(convo))} · ${fmtTime(entry.targetAt)} <button class="mini-btn" data-cancel-schedule="${entry.id}">Cancel</button></div>`).join('')}</div>` : ''}
    </div>
  `;
}

function renderMessage(message){
  const mine = message.sender === state.session.username;
  const senderInfo = state.directory.find(entry => entry.username === message.sender);
  const senderName = mine ? 'You' : (senderInfo ? senderInfo.displayName : message.sender);
  let body = '';
  if (message.type === 'text'){ body = `<div>${escapeHtml(bufToStr(message._plainBuf || strToBuf('')))}</div>`; }
  else {
    const blob = new Blob([message._plainBuf], { type: message.mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    state.objectUrls.push(url);
    if (message.type === 'image'){ body = `<div><img src="${url}" /></div>`; }
    else { body = `<a class="file-chip" href="${url}" download="${escapeHtml(message.filename || 'file')}" data-download-id="${message.id}">${fileSvg()} ${escapeHtml(message.filename || 'file')}</a>`; }
  }

  const previewText = message.type === 'text' ? bufToStr(message._plainBuf || strToBuf('')) : (message.filename || '');
  const replyMarkup = message.replyTo ? `<div class="reply-preview">↳ ${escapeHtml(shortPreview(previewText, 60))}</div>` : '';
  const actionMarkup = mine ? `<div class="message-actions"><button class="mini-btn" data-edit-id="${message.id}">Edit</button><button class="mini-btn" data-delete-id="${message.id}">Delete</button><button class="mini-btn" data-forward-id="${message.id}">Forward</button></div>` : `<div class="message-actions"><button class="mini-btn" data-reply-id="${message.id}">Reply</button><button class="mini-btn" data-forward-id="${message.id}">Forward</button></div>`;
  const status = getMessageStatus(message);
  const seenAt = getSeenAt(message);
  return `
    <div class="msg-row ${mine ? 'mine' : 'theirs'}">
      <div class="msg-sender">${escapeHtml(senderName)}</div>
      <div class="bubble">${replyMarkup}${body}</div>
      <div class="msg-foot">
        <span class="msg-time">${fmtTime(message.ts)}</span>
        ${message.type !== 'text' ? `<button class="save-btn" data-download-id="${message.id}">Download</button>` : ''}
        <span class="status-chip">${escapeHtml(status)}${seenAt ? ` · ${escapeHtml(seenAt)}` : ''}</span>
        ${actionMarkup}
      </div>
    </div>
  `;
}

function renderNewChatModal(){
  const others = state.directory.filter(entry => entry.username !== state.session.username);
  return `
    <div class="modal-bg" id="modalBg">
      <div class="modal">
        <div class="modal-body">
          <h3>New private chat</h3>
          <div class="modal-sub">Pick one person for a one-to-one or group chat. Every message is sealed individually to each person's key.</div>
          <div class="user-list">${others.length === 0 ? '<div class="empty-side">Nobody else has joined yet — share this page with a friend.</div>' : ''}${others.map(user => `<label class="user-pick"><input type="checkbox" value="${escapeHtml(user.username)}" ${state.ui.picked.includes(user.username) ? 'checked' : ''} /><div class="avatar">${escapeHtml(initials(user.displayName))}</div><div><div style="font-size:13.5px;font-weight:600;">${escapeHtml(user.displayName)}</div><div style="font-size:11px;color:var(--muted);font-family:var(--mono);">@${escapeHtml(user.username)}</div></div></label>`).join('')}</div>
          ${state.ui.picked.length > 1 ? '<input type="text" id="groupName" placeholder="Group name" style="margin-bottom:14px;" />' : ''}
          <div class="modal-footer"><button class="btn ghost" id="modalCancel" style="flex:1;">Cancel</button><button class="btn" id="modalGo" style="flex:1;" ${state.ui.picked.length === 0 ? 'disabled' : ''}>${state.ui.picked.length > 1 ? 'Create group' : 'Start chat'}</button></div>
        </div>
      </div>
    </div>
  `;
}

function renderProfileModal(){
  const draft = state.ui.profileDraft;
  return `
    <div class="modal-bg" id="profileBg">
      <div class="modal">
        <div class="modal-body">
          <h3>Profile</h3>
          <div class="modal-sub">Display name, bio, and avatar help people recognize you while keeping the chat encrypted.</div>
          <label>display name</label><input id="profileDisplay" value="${escapeHtml(draft.displayName || state.session.displayName || '')}" />
          <label>bio</label><input id="profileBio" value="${escapeHtml(draft.bio || '')}" />
          <label>retention</label><select id="retentionDays">
            <option value="3" ${draft.retentionDays === 3 ? 'selected' : ''}>3 days</option>
            <option value="7" ${draft.retentionDays === 7 ? 'selected' : ''}>7 days</option>
            <option value="15" ${draft.retentionDays === 15 ? 'selected' : ''}>15 days</option>
            <option value="30" ${draft.retentionDays === 30 ? 'selected' : ''}>30 days</option>
          </select>
          <label>avatar (optional)</label><input id="profileAvatar" type="file" accept="image/*" />
          <div class="hint">Messages and files are auto-deleted after the selected retention period. Screenshots cannot be completely prevented in a web app.</div>
          <div class="modal-footer"><button class="btn ghost" id="profileCancel" style="flex:1;">Cancel</button><button class="btn" id="profileSave" style="flex:1;">Save</button></div>
        </div>
      </div>
    </div>
  `;
}

function renderScheduleModal(){
  return `
    <div class="modal-bg" id="scheduleBg">
      <div class="modal">
        <div class="modal-body">
          <h3>Schedule</h3>
          <div class="modal-sub">Choose a future time. The message stays encrypted until then.</div>
          <label>send at</label><input id="scheduleWhen" type="datetime-local" value="${escapeHtml(state.ui.scheduleDraft.when || '')}" />
          <label>message</label><textarea id="scheduleText" rows="3">${escapeHtml(state.ui.scheduleDraft.text || '')}</textarea>
          <div class="modal-footer"><button class="btn ghost" id="scheduleCancel" style="flex:1;">Cancel</button><button class="btn" id="scheduleSave" style="flex:1;">Schedule</button></div>
        </div>
      </div>
    </div>
  `;
}

function attachAppListeners(){
  document.getElementById('btnLogout')?.addEventListener('click', logOut);
  document.getElementById('btnProfile')?.addEventListener('click', async () => {
    const account = await FirebaseStore.getJSON('account:' + state.session.username);
    state.ui.profileDraft = { displayName: state.session.displayName || '', bio: account?.profile?.bio || '', avatar: account?.profile?.avatar || '', retentionDays: Number(account?.retentionDays || 30) };
    state.ui.showProfile = true;
    render();
  });
  document.getElementById('btnPrivacy')?.addEventListener('click', () => setPrivacyMode(!state.ui.privacyMode));
  document.getElementById('btnNewChat')?.addEventListener('click', () => { state.ui.showNewChat = true; state.ui.picked = []; render(); });
  document.getElementById('searchConvos')?.addEventListener('input', e => { state.ui.search = e.target.value; render(); });

  root.querySelectorAll('.convo').forEach(convoEl => convoEl.addEventListener('click', async () => {
    state.activeConvoId = convoEl.dataset.id;
    await safely(async () => { await loadMessages(state.activeConvoId); render(); const list = document.getElementById('msgList'); if (list) list.scrollTop = list.scrollHeight; }, 'Could not load that conversation — check your connection and try again.');
  }));

  root.querySelectorAll('[data-pin-id]').forEach(btn => btn.addEventListener('click', e => { e.stopPropagation(); togglePin(btn.dataset.pinId); }));
  root.querySelectorAll('[data-archive-id]').forEach(btn => btn.addEventListener('click', e => { e.stopPropagation(); toggleArchive(btn.dataset.archiveId); }));
  root.querySelectorAll('[data-block-id]').forEach(btn => btn.addEventListener('click', async e => { e.stopPropagation(); const convo = state.convos.find(c => c.id === btn.dataset.blockId) || state.archivedConvos?.find(c => c.id === btn.dataset.blockId); const otherUsername = convo?.members.find(m => m !== state.session.username); if (otherUsername) await toggleBlockUser(otherUsername); }));

  const msgList = document.getElementById('msgList'); if (msgList) msgList.scrollTop = msgList.scrollHeight;
  document.getElementById('messageSearch')?.addEventListener('input', e => { state.ui.messageSearch = e.target.value; render(); });

  root.querySelectorAll('[data-save-id]').forEach(el => el.addEventListener('click', () => safely(() => markSaved(el.dataset.saveId), 'Could not save that message right now.')));
  root.querySelectorAll('[data-download-id]').forEach(el => el.addEventListener('click', async () => {
    const message = (state.messagesCache[state.activeConvoId] || []).find(entry => entry.id === el.dataset.downloadId);
    if (!message) return;
    const token = { id: 'download:' + message.id, expiresAt: Date.now() + 15_000, usedAt: Date.now() };
    await FirebaseStore.setJSON('download:' + message.id, token);
    setTimeout(() => FirebaseStore.deleteJSON('download:' + message.id).catch(() => {}), 15_000);
    toast('Temporary download link active for 15 seconds.');
  }));
  root.querySelectorAll('[data-edit-id]').forEach(el => el.addEventListener('click', () => editMessage(el.dataset.editId)));
  root.querySelectorAll('[data-delete-id]').forEach(el => el.addEventListener('click', () => deleteMessage(el.dataset.deleteId)));
  root.querySelectorAll('[data-forward-id]').forEach(el => el.addEventListener('click', () => forwardMessage(el.dataset.forwardId)));
  root.querySelectorAll('[data-reply-id]').forEach(el => el.addEventListener('click', () => { const reply = el.dataset.replyId; state.ui.scheduleDraft.text = `Replying to ${reply}`; window.prompt('Replying to message', ''); }));
  root.querySelectorAll('[data-cancel-schedule]').forEach(el => el.addEventListener('click', () => cancelScheduled(el.dataset.cancelSchedule)));

  const textInput = document.getElementById('textInput'); const btnSend = document.getElementById('btnSend'); const fileInput = document.getElementById('fileInput');
  if (textInput){ textInput.addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey){ event.preventDefault(); doSendText(); } }); }
  if (btnSend) btnSend.addEventListener('click', doSendText);
  if (fileInput) fileInput.addEventListener('change', async (event) => { const file = event.target.files[0]; if (!file) return; const type = file.type.startsWith('image/') ? 'image' : 'file'; await safely(async () => { await sendMessage({ type, file }); }, 'Could not send that file — check your connection and try again.'); fileInput.value = ''; });

  async function doSendText(){
    const text = textInput.value;
    if (!text.trim()) return;
    textInput.value = '';
    await safely(async () => { await sendMessage({ type: 'text', text }); }, 'Message did not send — check your connection and try again.');
  }

  document.getElementById('btnMic')?.addEventListener('click', startVoiceCapture);
  document.getElementById('btnEmoji')?.addEventListener('click', () => { state.ui.showEmoji = !state.ui.showEmoji; render(); });
  root.querySelectorAll('.emoji-btn').forEach(btn => btn.addEventListener('click', () => { if (textInput){ textInput.value += btn.dataset.emoji; textInput.focus(); } state.ui.showEmoji = false; render(); }));
  document.getElementById('btnSchedule')?.addEventListener('click', () => { state.ui.showSchedule = true; state.ui.scheduleDraft = { text: textInput.value, when: '' }; render(); });
  document.getElementById('scheduleSave')?.addEventListener('click', async () => { const text = document.getElementById('scheduleText').value; state.ui.scheduleDraft.text = text; state.ui.scheduleDraft.when = document.getElementById('scheduleWhen').value; await scheduleMessage(text); });
  document.getElementById('scheduleCancel')?.addEventListener('click', () => { state.ui.showSchedule = false; render(); });
  document.getElementById('profileSave')?.addEventListener('click', async () => { state.ui.profileDraft.displayName = document.getElementById('profileDisplay').value; state.ui.profileDraft.bio = document.getElementById('profileBio').value; state.ui.profileDraft.retentionDays = Number(document.getElementById('retentionDays').value || 30); const avatarInput = document.getElementById('profileAvatar'); if (avatarInput?.files?.[0]){ const file = avatarInput.files[0]; const reader = new FileReader(); reader.onload = () => { state.ui.profileDraft.avatar = reader.result; saveProfile(); }; reader.readAsDataURL(file); } else { await saveProfile(); } });
  document.getElementById('profileCancel')?.addEventListener('click', () => { state.ui.showProfile = false; render(); });
  document.getElementById('btnVoiceSend')?.addEventListener('click', async () => { const value = document.getElementById('voiceTextEdit').value; state.ui.voiceText = ''; state.ui.voiceStatus = 'idle'; await sendMessage({ type: 'text', text: value }); });

  document.getElementById('modalBg')?.addEventListener('click', e => { if (e.target.id === 'modalBg'){ state.ui.showNewChat = false; render(); } });
  document.getElementById('modalCancel')?.addEventListener('click', () => { state.ui.showNewChat = false; render(); });
  root.querySelectorAll('.user-pick input').forEach(cb => cb.addEventListener('change', () => { if (cb.checked) state.ui.picked.push(cb.value); else state.ui.picked = state.ui.picked.filter(value => value !== cb.value); state.ui.showNewChat = true; render(); }));
  document.getElementById('modalGo')?.addEventListener('click', async () => { state.ui.showNewChat = false; await safely(async () => { if (state.ui.picked.length === 1){ await openOrCreateDM(state.ui.picked[0]); } else if (state.ui.picked.length > 1){ const name = document.getElementById('groupName')?.value || ''; await createGroup(name, state.ui.picked); } }, 'Could not start that chat — check your connection and try again.'); state.ui.picked = []; });

  document.getElementById('profileBg')?.addEventListener('click', e => { if (e.target.id === 'profileBg'){ state.ui.showProfile = false; render(); } });
  document.getElementById('scheduleBg')?.addEventListener('click', e => { if (e.target.id === 'scheduleBg'){ state.ui.showSchedule = false; render(); } });

  document.body.addEventListener('dragover', event => { event.preventDefault(); });
  document.body.addEventListener('drop', async event => { event.preventDefault(); const file = event.dataTransfer?.files?.[0]; if (file){ const type = file.type.startsWith('image/') ? 'image' : 'file'; await safely(async () => { await sendMessage({ type, file }); }, 'Could not send that dropped file.'); } });
}

function startVoiceCapture(){
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition){ toast('Speech recognition is not available in this browser.'); return; }
  const recognition = new SpeechRecognition();
  recognition.lang = 'en-US';
  recognition.continuous = false;
  recognition.interimResults = false;
  state.ui.voiceStatus = 'Listening…';
  state.ui.voiceText = '';
  render();
  recognition.onresult = event => {
    const text = Array.from(event.results).map(result => result[0].transcript).join(' ').trim();
    state.ui.voiceText = text;
    state.ui.voiceStatus = 'Transcript ready — edit and send.';
    render();
  };
  recognition.onerror = () => { state.ui.voiceStatus = 'Speech recognition failed.'; render(); };
  recognition.onend = () => { if (state.ui.voiceStatus === 'Listening…') state.ui.voiceStatus = 'Idle'; render(); };
  recognition.start();
}

function sealSvg(){ return `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-4z" fill="#0B0D12" opacity="0.85"/><path d="M8.5 12.2l2.4 2.4 4.6-4.9" stroke="#E8A33D" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`; }
function logoutSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>`; }
function profileSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 12a4 4 0 100-8 4 4 0 000 8zm8 8a8 8 0 00-16 0"/></svg>`; }
function shieldSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3z"/></svg>`; }
function clipSvg(){ return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a5 5 0 01-7.07-7.07l9.19-9.19a3.5 3.5 0 014.95 4.95L9.41 17.86a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>`; }
function sendSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0B0D12" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>`; }
function fileSvg(){ return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>`; }
function micSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 14a3 3 0 003-3V6a3 3 0 00-6 0v5a3 3 0 003 3z"/><path d="M19 11a7 7 0 01-14 0"/><path d="M12 18v3"/><path d="M8 21h8"/></svg>`; }
function emojiSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="9" cy="10" r="1"/><circle cx="15" cy="10" r="1"/><path d="M8 15c1 1 2.6 1.7 4 1.7s3-.7 4-1.7"/></svg>`; }
function clockSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`; }
function archiveSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 8h18"/><path d="M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8"/><path d="M9 12h6"/></svg>`; }
function blockSvg(){ return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8"/><path d="M6 6l12 12"/></svg>`; }

async function initializeApp(){
  window.addEventListener('online', () => { setOnlineStatus(true); flushPendingMessages(); });
  window.addEventListener('offline', () => setOnlineStatus(false));
  document.addEventListener('visibilitychange', applyVisibility);
  setOnlineStatus(navigator.onLine);
  await restoreSessionState();
  render();
}

initializeApp();
