/* ============================================================================
   utils.js — small, generic helpers with no dependency on app state.
   Loaded first (after config.js) so every other file can use these freely.
   ========================================================================= */

const $ = sel => document.querySelector(sel);

// Wraps any promise with a timeout, so a hung network call fails loudly with
// a clear message instead of leaving the UI stuck forever with no feedback.
function withTimeout(promise, ms, label){
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(
      () => reject(new Error(label + ' timed out after ' + (ms/1000) + 's — the database may be unreachable right now. Try again.')),
      ms
    ))
  ]);
}

// ---- binary <-> base64/string conversions, used throughout crypto.js ----
function buf2b64(buf){
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b642buf(b64){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function strToBuf(str){ return new TextEncoder().encode(str); }
function bufToStr(buf){ return new TextDecoder().decode(buf); }

// ---- small UI helpers ----
function initials(name){
  return (name||'?').trim().split(/\s+/).slice(0,2).map(w=>w[0]?.toUpperCase()||'').join('');
}
function fmtTime(ts){
  const d = new Date(ts);
  return d.toLocaleString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
}
function randomId(){ return buf2b64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^a-zA-Z0-9]/g,'').slice(0,16); }
function escapeHtml(s){
  return (s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function toast(msg){
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2400);
}
// Runs an async UI action and turns any failure into a toast instead of a
// silent no-op, so network hiccups during normal use are never invisible.
async function safely(fn, failMsg){
  try{ await fn(); }
  catch(e){ toast(failMsg || ('Connection hiccup: ' + (e.message || 'try again'))); }
}
