function sanitizeText(value){
  return String(value || '').trim();
}

function sanitizeUsername(value){
  return sanitizeText(value).toLowerCase().replace(/[^a-z0-9._-]/g, '');
}

function normalizeDisplayName(value){
  return sanitizeText(value).replace(/\s+/g, ' ');
}

function escapeHtml(s){
  return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function buf2b64(buf){
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b642buf(b64){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function strToBuf(str){ return new TextEncoder().encode(str); }
function bufToStr(buf){ return new TextDecoder().decode(buf); }
function initials(name){ return (name || '?').trim().split(/\s+/).slice(0, 2).map(w => w[0]?.toUpperCase() || '').join(''); }
function fmtTime(ts){ const d = new Date(ts); return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function randomId(){ return buf2b64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^a-zA-Z0-9]/g, '').slice(0, 16); }
function keyToPath(key){ return String(key).replace(/:/g, '/'); }
function withTimeout(promise, ms, label){ return Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(label + ' timed out after ' + (ms/1000) + 's — the database may be unreachable right now. Try again.')), ms))]); }
function clone(value){ return JSON.parse(JSON.stringify(value)); }
function isObject(value){ return value !== null && typeof value === 'object' && !Array.isArray(value); }
function shortPreview(text, max = APP_CONFIG.MAX_MESSAGE_PREVIEW_LENGTH){ return (text || '').slice(0, max); }
function logDebug(...args){ if (APP_CONFIG.DEV_MODE) console.debug('[sealed]', ...args); }

async function safely(fn, failMsg){
  try{ await fn(); }
  catch(e){ toast(failMsg || ('Connection hiccup: ' + (e.message || 'try again'))); }
}
