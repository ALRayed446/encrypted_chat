/* ============================================================================
   app.js — WhatsApp-Style UI + Voice Messages
   ========================================================================= */

const root = $('#root');
console.log('🚀 Sealed v2.2 loading...');

// ---- VERSION CHECK ----
const APP_VERSION = '2.2';
if (localStorage.getItem('sealed_version') !== APP_VERSION) {
  localStorage.setItem('sealed_version', APP_VERSION);
  window._forceRebuild = true;
}

// ---- AUTO-LOGIN ----
(async function autoLogin() {
  const saved = localStorage.getItem('sealed_creds');
  if (saved) {
    try {
      const { username, password } = JSON.parse(atob(saved));
      if (username && password) window._autoLoginData = { username, password };
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
  replyingTo: null,
};

// ---- VOICE RECORDER STATE ----
let voiceRecorder = {
  mediaRecorder: null,
  audioChunks: [],
  isRecording: false,
  startTime: null,
  timerInterval: null,
  stream: null,
  duration: 0,
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
  btnVoice: null,
  voicePreview: null,
  voiceTimer: null,
  voiceCancelBtn: null,
  voiceSendBtn: null,
};

// ---- 3. HELPERS ----
function getOtherUsername(convo) {
  if (convo.type === 'dm') return convo.members.find(m => m !== session.username);
  return null;
}

function getUserAvatar(username) {
  if (username === session.username) return session.avatar;
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

function getLastMessagePreview(convoId) {
  const msgs = messagesCache[convoId] || [];
  if (msgs.length === 0) return 'Tap to chat';
  const last = msgs[msgs.length - 1];
  if (last.type === 'text') return bufToStr(last._plainBuf);
  if (last.type === 'image') return '📷 Photo';
  if (last.type === 'audio') return '🎤 Voice message';
  return '📎 File';
}

function formatTimeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000) return Math.floor(diff / 1000) + 's';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
  if (diff < 604800000) return Math.floor(diff / 86400000) + 'd';
  return new Date(ts).toLocaleDateString();
}

function formatDuration(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return String(mins).padStart(2, '0') + ':' + String(secs).padStart(2, '0');
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

async function updateLastSeen() {
  if (!session.username) return;
  const account = await getJSON('account:'+session.username, true);
  if (!account) return;
  account.lastSeen = Date.now();
  await setJSON('account:'+session.username, account, true);
  const entry = directory.find(d => d.username === session.username);
  if (entry) entry.lastSeen = Date.now();
}

// ---- 6. BLOCK SYSTEM ----
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

// ---- 7. CONVERSATIONS ----
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

// ---- 8. MESSAGES ----
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
  
  const convo = convos.find(c => c.id === convoId);
  if (convo && decrypted.length > 0) {
    const last = decrypted[decrypted.length - 1];
    if (last.type === 'text') convo.lastMessagePreview = bufToStr(last._plainBuf);
    else if (last.type === 'image') convo.lastMessagePreview = '📷 Photo';
    else if (last.type === 'audio') convo.lastMessagePreview = '🎤 Voice message';
    else convo.lastMessagePreview = '📎 File';
    convo.lastMessageTime = last.ts;
  }
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

async function sendMessage({type, text, file, audioBlob, duration}) {
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

  let bytes, filename=null, mime=null, audioDuration=null;

  if (type === 'text') {
    if (!text.trim()) return;
    bytes = strToBuf(text.trim());
  } else if (type === 'audio') {
    // Voice message: audioBlob is a Blob
    if (!audioBlob) return;
    bytes = await audioBlob.arrayBuffer();
    mime = audioBlob.type || 'audio/webm';
    filename = 'voice-message.webm';
    audioDuration = duration || 0;
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
    replyToPreview = ui.replyingTo.preview || '[File/Image]';
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
    duration: audioDuration, // for voice messages
  };

  const list = (await getJSON('messages:'+convo.id, true)) || [];
  list.push(msg);
  await setJSON('messages:'+convo.id, list, true);

  convo.lastActivity = Date.now();
  if (type === 'text') convo.lastMessagePreview = text.trim();
  else if (type === 'image') convo.lastMessagePreview = '📷 Photo';
  else if (type === 'audio') convo.lastMessagePreview = '🎤 Voice message';
  else convo.lastMessagePreview = '📎 File';
  convo.lastMessageTime = Date.now();
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

// ---- 9. VOICE RECORDING ----
function formatVoiceDuration(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return String(mins).padStart(2, '0') + ':' + String(secs).padStart(2, '0');
}

async function startVoiceRecording() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mediaRecorder = new MediaRecorder(stream, {
      mimeType: MediaRecorder.isTypeSupported('audio/webm;codecs=opus') 
        ? 'audio/webm;codecs=opus' 
        : 'audio/webm'
    });
    
    voiceRecorder.stream = stream;
    voiceRecorder.mediaRecorder = mediaRecorder;
    voiceRecorder.audioChunks = [];
    voiceRecorder.isRecording = true;
    voiceRecorder.startTime = Date.now();
    voiceRecorder.duration = 0;

    mediaRecorder.ondataavailable = (e) => {
      if (e.data.size > 0) voiceRecorder.audioChunks.push(e.data);
    };

    mediaRecorder.onstop = () => {
      voiceRecorder.isRecording = false;
      if (voiceRecorder.timerInterval) {
        clearInterval(voiceRecorder.timerInterval);
        voiceRecorder.timerInterval = null;
      }
      // Show preview
      showVoicePreview();
    };

    // Start timer
    voiceRecorder.timerInterval = setInterval(() => {
      voiceRecorder.duration = (Date.now() - voiceRecorder.startTime) / 1000;
      if (dom.voiceTimer) {
        dom.voiceTimer.textContent = formatVoiceDuration(voiceRecorder.duration);
      }
    }, 200);

    mediaRecorder.start();
    updateVoiceUI('recording');
    toast('Recording...');
  } catch (err) {
    toast('Microphone access denied. Please allow microphone permissions.');
    console.error('Voice recording error:', err);
  }
}

function stopVoiceRecording() {
  if (voiceRecorder.mediaRecorder && voiceRecorder.isRecording) {
    voiceRecorder.mediaRecorder.stop();
    // Stop all tracks
    if (voiceRecorder.stream) {
      voiceRecorder.stream.getTracks().forEach(track => track.stop());
    }
    if (voiceRecorder.timerInterval) {
      clearInterval(voiceRecorder.timerInterval);
      voiceRecorder.timerInterval = null;
    }
    toast('Recording finished');
  }
}

function cancelVoiceRecording() {
  if (voiceRecorder.mediaRecorder && voiceRecorder.isRecording) {
    voiceRecorder.mediaRecorder.stop();
    if (voiceRecorder.stream) {
      voiceRecorder.stream.getTracks().forEach(track => track.stop());
    }
    if (voiceRecorder.timerInterval) {
      clearInterval(voiceRecorder.timerInterval);
      voiceRecorder.timerInterval = null;
    }
  }
  voiceRecorder.audioChunks = [];
  voiceRecorder.isRecording = false;
  voiceRecorder.duration = 0;
  updateVoiceUI('idle');
  toast('Recording cancelled');
}

function showVoicePreview() {
  if (voiceRecorder.audioChunks.length === 0) {
    toast('No audio recorded.');
    updateVoiceUI('idle');
    return;
  }
  const blob = new Blob(voiceRecorder.audioChunks, { 
    type: MediaRecorder.isTypeSupported('audio/webm;codecs=opus') 
      ? 'audio/webm;codecs=opus' 
      : 'audio/webm' 
  });
  const url = URL.createObjectURL(blob);
  // Store for sending
  voiceRecorder._previewBlob = blob;
  voiceRecorder._previewUrl = url;
  voiceRecorder._duration = voiceRecorder.duration;
  
  updateVoiceUI('preview');
  // Set audio preview
  const audioEl = document.getElementById('voicePreviewAudio');
  if (audioEl) {
    audioEl.src = url;
    audioEl.load();
  }
  if (dom.voiceTimer) {
    dom.voiceTimer.textContent = formatVoiceDuration(voiceRecorder.duration);
  }
}

async function sendVoiceMessage() {
  if (!voiceRecorder._previewBlob) return;
  const blob = voiceRecorder._previewBlob;
  const duration = voiceRecorder._duration || 0;
  
  // Send the voice message
  await safely(async () => {
    await sendMessage({
      type: 'audio',
      audioBlob: blob,
      duration: duration
    });
  }, 'Could not send voice message.');
  
  // Clean up
  if (voiceRecorder._previewUrl) {
    URL.revokeObjectURL(voiceRecorder._previewUrl);
  }
  voiceRecorder._previewBlob = null;
  voiceRecorder._previewUrl = null;
  voiceRecorder.audioChunks = [];
  voiceRecorder.duration = 0;
  updateVoiceUI('idle');
  dom.msgList.scrollTop = dom.msgList.scrollHeight;
}

function updateVoiceUI(state) {
  const btnVoice = dom.btnVoice;
  const voicePreview = dom.voicePreview;
  const voiceTimer = dom.voiceTimer;
  const textInput = dom.textInput;
  const btnSend = dom.btnSend;

  if (!btnVoice) return;

  if (state === 'recording') {
    btnVoice.textContent = '⏹';
    btnVoice.style.color = 'var(--danger)';
    btnVoice.title = 'Stop recording';
    if (voicePreview) voicePreview.style.display = 'flex';
    if (voiceTimer) voiceTimer.textContent = '00:00';
    if (textInput) textInput.disabled = true;
    if (btnSend) btnSend.style.display = 'none';
    // Show cancel + send in preview
    if (dom.voiceCancelBtn) dom.voiceCancelBtn.style.display = 'inline-block';
    if (dom.voiceSendBtn) dom.voiceSendBtn.style.display = 'none';
  } else if (state === 'preview') {
    btnVoice.textContent = '🎤';
    btnVoice.style.color = '';
    btnVoice.title = 'Record voice message';
    if (voicePreview) voicePreview.style.display = 'flex';
    if (textInput) textInput.disabled = true;
    if (btnSend) btnSend.style.display = 'none';
    if (dom.voiceCancelBtn) dom.voiceCancelBtn.style.display = 'inline-block';
    if (dom.voiceSendBtn) dom.voiceSendBtn.style.display = 'inline-block';
  } else {
    // idle
    btnVoice.textContent = '🎤';
    btnVoice.style.color = '';
    btnVoice.title = 'Record voice message';
    if (voicePreview) voicePreview.style.display = 'none';
    if (textInput) textInput.disabled = false;
    if (btnSend) btnSend.style.display = 'flex';
    if (dom.voiceCancelBtn) dom.voiceCancelBtn.style.display = 'none';
    if (dom.voiceSendBtn) dom.voiceSendBtn.style.display = 'none';
    // Clean up preview audio
    const audioEl = document.getElementById('voicePreviewAudio');
    if (audioEl) {
      audioEl.pause();
      audioEl.src = '';
    }
  }
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
    el.style.background = 'rgba(0,229,160,0.15)';
    setTimeout(() => el.style.background = '', 2000);
  } else {
    toast('Original message not loaded.');
  }
}

// ----- BUILD SHELL (WhatsApp Style + Voice) -----
function buildShell() {
  if (dom.shell && !window._forceRebuild) return;
  console.log('🔄 Building WhatsApp-style shell with voice...');

  dom.root.innerHTML = `
    <div class="shell" id="appShell">
      <!-- SIDEBAR -->
      <div class="sidebar" id="sidebar">
        <div class="sb-head">
          <div class="me">
            <div class="avatar" id="myAvatar" style="position:relative; cursor:pointer;">
              ${session.avatar ? `<img src="${session.avatar}" />` : escapeHtml(initials(session.displayName))}
              <span class="avatar-edit" id="avatarEditBtn" title="Change profile picture">✎</span>
            </div>
            <div class="me-name">${escapeHtml(session.displayName)}</div>
          </div>
          <div style="display:flex; gap:4px;">
            <button class="icon-btn" id="btnNewChat" title="New chat">✏️</button>
            <button class="icon-btn" id="btnLogout" title="Log out">⏻</button>
          </div>
        </div>
        <div class="sb-search">
          <input type="text" id="searchChats" placeholder="Search or start a new chat" />
        </div>
        <div class="convo-list" id="convoList"></div>
      </div>

      <!-- MAIN -->
      <div class="main" id="mainArea">
        <div class="no-chat" id="noChat">
          <div class="no-chat-icon">${sealSvg()}</div>
          <div class="no-chat-title">Sealed</div>
          <div class="no-chat-sub">Send and receive messages securely</div>
          <div class="no-chat-hint">End-to-end encrypted</div>
        </div>

        <div class="chat-area" id="chatArea" style="display:none;">
          <div class="chat-head" id="chatHead">
            <div class="chat-head-left">
              <div class="chat-head-avatar" id="chatHeadAvatar"></div>
              <div>
                <div class="chat-head-title" id="chatHeadTitle"></div>
                <div class="chat-head-sub" id="chatHeadSub"></div>
              </div>
            </div>
            <div class="chat-head-right">
              <button class="icon-btn" id="btnBlock" title="Block">⛔</button>
              <button class="icon-btn" id="btnPrivacy" title="Privacy mode">👁</button>
              <div class="seal" title="Encrypted">${sealSvg()}</div>
            </div>
          </div>

          <div class="messages" id="msgList"></div>

          <div class="composer" id="composerArea">
            <div id="replyBar" style="display:none;">
              <div>
                <span style="color:var(--accent);">Replying to <span id="replySender"></span></span>
                <div id="replyPreviewText"></div>
              </div>
              <button id="cancelReplyBtn">✕</button>
            </div>
            <div class="composer-row">
              <button class="icon-btn" id="btnVoice" title="Voice message" style="font-size:22px;">🎤</button>
              <select id="expiryPicker" style="background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:4px 6px;font-size:11px;cursor:pointer;">
                <option value="">Off</option>
                <option value="60000">1m</option>
                <option value="300000">5m</option>
                <option value="1800000">30m</option>
                <option value="3600000">1h</option>
                <option value="86400000">24h</option>
              </select>
              <label class="icon-btn" style="cursor:pointer;font-size:20px;">
                📎
                <input type="file" id="fileInput" style="display:none" />
              </label>
              <textarea id="textInput" rows="1" placeholder="Type a message"></textarea>
              <button class="send-btn" id="btnSend">➤</button>
            </div>
            <!-- Voice Preview (hidden by default) -->
            <div id="voicePreview" style="display:none; background:var(--surface); border-radius:8px; padding:8px 12px; margin-top:6px; align-items:center; gap:12px; border:1px solid var(--line);">
              <audio id="voicePreviewAudio" controls style="flex:1; max-width:200px; height:36px; background:var(--bg); border-radius:6px;"></audio>
              <span id="voiceTimer" style="font-family:var(--mono); font-size:13px; color:var(--text); min-width:40px;">00:00</span>
              <button id="voiceCancelBtn" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:18px;padding:0 6px;" title="Cancel">✕</button>
              <button id="voiceSendBtn" style="background:var(--accent);border:none;border-radius:50%;width:36px;height:36px;cursor:pointer;font-size:16px;color:#000;display:none;" title="Send voice">➤</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Hidden avatar input
  let avatarInput = document.getElementById('avatarFileInput');
  if (!avatarInput) {
    avatarInput = document.createElement('input');
    avatarInput.type = 'file';
    avatarInput.id = 'avatarFileInput';
    avatarInput.accept = 'image/*';
    avatarInput.style.display = 'none';
    document.body.appendChild(avatarInput);
  }

  dom.shell = $('#appShell');
  dom.sidebar = $('#sidebar');
  dom.convoList = $('#convoList');
  dom.mainArea = $('#mainArea');
  dom.chatArea = $('#chatArea');
  dom.noChat = $('#noChat');
  dom.chatHead = $('#chatHead');
  dom.chatHeadTitle = $('#chatHeadTitle');
  dom.chatHeadSub = $('#chatHeadSub');
  dom.chatHeadAvatar = $('#chatHeadAvatar');
  dom.msgList = $('#msgList');
  dom.composerArea = $('#composerArea');
  dom.replyBar = $('#replyBar');
  dom.textInput = $('#textInput');
  dom.btnSend = $('#btnSend');
  dom.fileInput = $('#fileInput');
  dom.btnPrivacy = $('#btnPrivacy');
  dom.btnBlock = $('#btnBlock');
  dom.expiryPicker = $('#expiryPicker');
  dom.btnVoice = $('#btnVoice');
  dom.voicePreview = $('#voicePreview');
  dom.voiceTimer = $('#voiceTimer');
  dom.voiceCancelBtn = $('#voiceCancelBtn');
  dom.voiceSendBtn = $('#voiceSendBtn');

  attachStaticListeners(avatarInput);
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

// ----- UPDATERS (WhatsApp Style) -----
function updateSidebar() {
  const list = dom.convoList;
  if (!list) return;
  const scrollPos = list.scrollTop;

  list.innerHTML = convos.length === 0 ? `
    <div class="empty-side">
      <div style="font-size:14px; font-weight:600; margin-bottom:4px;">No chats</div>
      <div style="font-size:13px;">Start a new conversation</div>
    </div>
  ` : convos.map(c => {
    const title = convoTitle(c);
    const other = c.type === 'dm' ? getOtherUsername(c) : null;
    const avatar = other ? getUserAvatar(other) : null;
    const online = other ? isUserOnline(other) : false;
    const preview = c.lastMessagePreview || 'Tap to chat';
    const time = c.lastMessageTime ? formatTimeAgo(c.lastMessageTime) : '';
    const isActive = c.id === activeConvoId;

    return `
    <div class="convo ${isActive ? 'active' : ''}" data-id="${c.id}">
      <div class="convo-avatar">
        ${avatar ? `<img src="${avatar}" />` : `<span>${initials(title)}</span>`}
        ${online ? '<span class="online-dot"></span>' : ''}
      </div>
      <div class="convo-info">
        <div class="convo-row">
          <span class="convo-name">${escapeHtml(title)}</span>
          <span class="convo-time">${time}</span>
        </div>
        <div class="convo-row">
          <span class="convo-preview">${escapeHtml(preview)}</span>
        </div>
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

  const searchInput = $('#searchChats');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase().trim();
      list.querySelectorAll('.convo').forEach(el => {
        const name = el.querySelector('.convo-name')?.textContent?.toLowerCase() || '';
        el.style.display = name.includes(q) ? 'flex' : 'none';
      });
    });
  }
}

function updateChatHead() {
  if (!activeConvoId) return;
  const convo = convos.find(c => c.id === activeConvoId);
  if (!convo) return;
  
  const title = convoTitle(convo);
  dom.chatHeadTitle.textContent = title;
  
  const other = convo.type === 'dm' ? getOtherUsername(convo) : null;
  const avatar = other ? getUserAvatar(other) : null;
  dom.chatHeadAvatar.innerHTML = avatar ? `<img src="${avatar}" />` : initials(title);
  
  if (convo.type === 'dm' && other) {
    const online = isUserOnline(other);
    getTypingUsers(activeConvoId).then(users => {
      if (users.includes(other)) {
        dom.chatHeadSub.textContent = 'typing...';
        dom.chatHeadSub.style.color = 'var(--accent)';
      } else {
        dom.chatHeadSub.textContent = online ? 'Online' : formatLastSeen(directory.find(d => d.username === other)?.lastSeen);
        dom.chatHeadSub.style.color = 'var(--text-muted)';
      }
    });
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

  // Attach listeners for voice players
  dom.msgList.querySelectorAll('.voice-player').forEach(el => {
    const audio = el.querySelector('audio');
    const playBtn = el.querySelector('.voice-play-btn');
    const progress = el.querySelector('.voice-progress');
    const durationEl = el.querySelector('.voice-duration');
    
    if (audio && playBtn) {
      playBtn.addEventListener('click', () => {
        if (audio.paused) {
          // Pause other players
          document.querySelectorAll('.voice-player audio').forEach(a => {
            if (a !== audio) a.pause();
          });
          audio.play();
          playBtn.textContent = '⏸';
        } else {
          audio.pause();
          playBtn.textContent = '▶';
        }
      });
      audio.addEventListener('timeupdate', () => {
        if (progress) {
          const pct = (audio.currentTime / audio.duration) * 100;
          progress.style.width = pct + '%';
        }
      });
      audio.addEventListener('ended', () => {
        playBtn.textContent = '▶';
        if (progress) progress.style.width = '0%';
      });
      audio.addEventListener('loadedmetadata', () => {
        if (durationEl) {
          durationEl.textContent = formatDuration(audio.duration);
        }
      });
    }
  });

  dom.msgList.querySelectorAll('.msg-row').forEach(row => {
    const mid = row.dataset.msgId;
    if (!mid) return;
    const picker = row.querySelector('.reaction-picker');
    if (picker) {
      picker.querySelectorAll('.reaction-emoji').forEach(el => {
        el.addEventListener('click', (e) => {
          e.stopPropagation();
          safely(() => addReaction(mid, el.dataset.emoji), 'Could not add reaction.');
        });
      });
    }
    const replyBtn = row.querySelector('.reply-btn');
    if (replyBtn) {
      replyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const msg = messagesCache[activeConvoId].find(m => m.id === mid);
        if (!msg) return;
        const preview = msg.type === 'text' ? bufToStr(msg._plainBuf) : (msg.type === 'audio' ? '🎤 Voice message' : '[File/Image]');
        ui.replyingTo = { id: mid, sender: msg.sender, preview };
        renderApp();
        dom.textInput?.focus();
      });
    }
  });

  dom.msgList.querySelectorAll('.reply-preview').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const targetId = el.dataset.replyId;
      if (targetId) scrollToMessage(targetId);
    });
  });

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
      <div class="reply-preview" data-reply-id="${m.replyToId}">
        <span>↩️ ${getUserDisplayName(m.replyToPreview.sender || '')}</span>
        <div>${escapeHtml(m.replyToPreview)}</div>
      </div>
    `;
  }

  if (m.type === 'text') {
    body = `<div>${escapeHtml(bufToStr(m._plainBuf))}</div>`;
  } else if (m.type === 'audio') {
    // Voice message player
    const blob = new Blob([m._plainBuf], { type: m.mime || 'audio/webm' });
    const url = URL.createObjectURL(blob);
    const duration = m.duration || 0;
    body = `
      <div class="voice-player">
        <audio src="${url}" preload="metadata"></audio>
        <button class="voice-play-btn">▶</button>
        <div class="voice-progress-bar">
          <div class="voice-progress" style="width:0%;"></div>
        </div>
        <span class="voice-duration">${formatDuration(duration)}</span>
      </div>
    `;
  } else {
    const blob = new Blob([m._plainBuf], { type: m.mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    if (m.type === 'image') {
      body = `<div><img src="${url}" /></div>`;
    } else {
      body = `<a class="file-chip" href="${url}" download="${escapeHtml(m.filename||'file')}" data-download-id="${m.id}">📎 ${escapeHtml(m.filename||'file')}</a>`;
    }
  }

  let reactionsHtml = '';
  if (m.reactions) {
    const emojis = Object.values(m.reactions);
    if (emojis.length > 0) {
      const grouped = emojis.reduce((acc, em) => { acc[em] = (acc[em] || 0) + 1; return acc; }, {});
      reactionsHtml = `<div class="reactions">${Object.entries(grouped).map(([em, count]) => `<span class="reaction-badge">${em} ${count}</span>`).join('')}</div>`;
    }
  }

  const pickerHtml = `<div class="reaction-picker">${['👍','❤️','😂','😮','😢','🙏'].map(e => `<span class="reaction-emoji" data-emoji="${e}">${e}</span>`).join('')}</div>`;
  const replyBtnHtml = `<span class="reply-btn">↩️</span>`;

  let readStatus = '';
  if (!mine && m.readBy && m.readBy[session.username]) {
    readStatus = '<span class="read-status seen">✓✓</span>';
  } else if (!mine) {
    readStatus = '<span class="read-status">✓</span>';
  }

  let expiryInfo = '';
  if (m.expiresAt) {
    const remaining = Math.max(0, m.expiresAt - Date.now());
    if (remaining > 0) {
      const mins = Math.floor(remaining / 60000);
      const secs = Math.floor((remaining % 60000) / 1000);
      expiryInfo = `<span class="expiry-timer">⌛ ${mins}m ${secs}s</span>`;
    }
  }

  const savedMarkup = m.savedAt
    ? `<span class="save-btn saved">💾 ${timeLeft(m.savedAt)}</span>`
    : `<button class="save-btn" data-save-id="${m.id}">💾 Save</button>`;

  const avatarHtml = avatar ? `<img src="${avatar}" />` : '';

  return `
    <div class="msg-row ${mine ? 'mine' : 'theirs'}" data-msg-id="${m.id}">
      <div class="msg-sender">${avatarHtml} ${escapeHtml(senderName)}</div>
      <div class="bubble">
        ${replyHtml}
        ${body}
        ${pickerHtml}
        <div class="bubble-actions">
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
  if (!dom.shell || window._forceRebuild) {
    buildShell();
  } else {
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
  updateReplyBar();
  if (ui.showNewChat) renderNewChatModal();
  else { const modal = $('#modalBg'); if (modal) modal.remove(); }
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
          <div class="checkbox-row">
            <input type="checkbox" id="f-remember" ${ui.rememberMe ? 'checked' : ''} />
            <label for="f-remember">Remember me</label>
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
          <h3>New chat</h3>
          <div class="modal-sub">Select a contact to start a private chat, or pick multiple to create a group.</div>
          <input type="text" id="contactSearch" placeholder="Search contacts..." />
          <div class="user-list" id="userList">
            ${others.length===0 ? `<div class="empty-side">No contacts yet</div>` : ''}
            ${others.map(d => `
              <label class="user-pick" data-username="${escapeHtml(d.username)}">
                <input type="checkbox" value="${escapeHtml(d.username)}" ${ui.picked.includes(d.username)?'checked':''} />
                <div class="avatar">${d.avatar ? `<img src="${d.avatar}" />` : escapeHtml(initials(d.displayName))}</div>
                <div>
                  <div style="font-weight:600;">${escapeHtml(d.displayName)}</div>
                  <div style="font-size:12px;color:var(--text-muted);">@${escapeHtml(d.username)}</div>
                </div>
              </label>
            `).join('')}
          </div>
          ${ui.picked.length > 1 ? `<input type="text" id="groupName" placeholder="Group name" />` : ''}
          <div class="modal-footer">
            <button class="btn ghost" id="modalCancel">Cancel</button>
            <button class="btn" id="modalGo" ${ui.picked.length===0?'disabled':''}>${ui.picked.length>1?'Create group':'Start chat'}</button>
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
    if (e.target.id === 'modalBg') { ui.showNewChat = false; render(); }
  });
  $('#modalCancel')?.addEventListener('click', () => { ui.showNewChat = false; render(); });
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
  $('#btnLogout')?.addEventListener('click', logOut);
  $('#btnNewChat')?.addEventListener('click', () => {
    ui.showNewChat = true;
    ui.picked = [];
    render();
  });
  $('#btnPrivacy')?.addEventListener('click', () => {
    setPrivacyMode(!ui.privacyMode);
    render();
  });
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

  // Avatar
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

  dom.btnSend?.addEventListener('click', doSendText);
  dom.fileInput?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    await safely(async () => {
      await sendMessage({type, file});
    }, 'Could not send file.');
    dom.fileInput.value = '';
  });

  // ---- VOICE BUTTON ----
  dom.btnVoice?.addEventListener('click', () => {
    if (voiceRecorder.isRecording) {
      // Stop recording
      stopVoiceRecording();
    } else if (voiceRecorder._previewBlob) {
      // If preview is showing, do nothing (user should use send/cancel)
      return;
    } else {
      // Start recording
      startVoiceRecording();
    }
  });

  // Voice cancel
  dom.voiceCancelBtn?.addEventListener('click', () => {
    if (voiceRecorder.isRecording) {
      cancelVoiceRecording();
    } else {
      // Cancel preview
      if (voiceRecorder._previewUrl) {
        URL.revokeObjectURL(voiceRecorder._previewUrl);
      }
      voiceRecorder._previewBlob = null;
      voiceRecorder._previewUrl = null;
      voiceRecorder.audioChunks = [];
      voiceRecorder.duration = 0;
      updateVoiceUI('idle');
    }
  });

  // Voice send
  dom.voiceSendBtn?.addEventListener('click', sendVoiceMessage);

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

  const cancelReply = $('#cancelReplyBtn');
  if (cancelReply) {
    cancelReply.addEventListener('click', () => {
      ui.replyingTo = null;
      renderApp();
      dom.textInput?.focus();
    });
  }

  if (dom.expiryPicker) {
    dom.expiryPicker.addEventListener('change', () => {
      const val = dom.expiryPicker.value;
      ui.messageExpiry = val ? parseInt(val) : null;
    });
  }

  window.addEventListener('blur', handleWindowBlur);
  window.addEventListener('focus', handleWindowFocus);
  window.addEventListener('beforeunload', () => {
    if (session.username) updateLastSeen();
  });
}

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

// ---- 17. SVG HELPERS ----
function sealSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-4z" fill="#0B0D12" opacity="0.85"/><path d="M8.5 12.2l2.4 2.4 4.6-4.9" stroke="#E8A33D" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

// ---- 18. AUTO-LOGIN ----
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

// ---- 19. START ----
render();
console.log('✅ Sealed v2.2 ready (voice messages)');