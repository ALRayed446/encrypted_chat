/* ============================================================================
   crypto.js — every encryption operation in Sealed lives here.

   HOW THE ENCRYPTION ACTUALLY WORKS (read this, it's not decoration):
   - Every account gets an RSA-OAEP 2048 keypair, generated in your browser
     with the native Web Crypto API.
   - The PUBLIC key is stored openly (that's the point of a public key).
   - The PRIVATE key is encrypted with a key derived from your password via
     PBKDF2 (250,000 rounds) before it's ever written to storage. Your
     password itself is never stored or transmitted anywhere.
   - Every message gets its own random AES-256-GCM key. The message content
     is encrypted with that key. The AES key is then individually wrapped
     (RSA-OAEP encrypted) for each recipient's public key, and only those
     wrapped copies are stored.
   - Net effect: the storage layer (Firebase, see firebase.js) only ever
     sees ciphertext + wrapped keys. Only someone holding the matching
     private key (unlocked with the right password) can decrypt a message.

   HONEST LIMITATIONS (please read this too):
   - This is trust-on-first-use: there's no central authority verifying
     public keys, so use the "safety code" fingerprint shown for each
     contact to confirm keys match over a separate channel (call them, don't
     just trust the app) if you want protection against a compromised
     directory swapping someone's key.
   - There's no forward secrecy / key ratcheting like Signal — one leaked
     private key can decrypt that account's past messages.
   - Your private key is decrypted into memory only for this browser tab and
     is never written to disk — so you'll need to log in again each visit.
     Security is only as strong as your password.

   Depends on: buf2b64/b642buf/strToBuf/bufToStr (utils.js).
   Also references `directory` and `session` (declared in app.js) inside
   function bodies — that's safe because these functions are only ever
   called later, after app.js has already run and defined them.
   ========================================================================= */

async function deriveWrapKey(password, saltBytes){
  const baseKey = await crypto.subtle.importKey('raw', strToBuf(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt: saltBytes, iterations: 250000, hash: 'SHA-256' },
    baseKey, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}

async function generateKeypair(){
  return crypto.subtle.generateKey(
    { name:'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash:'SHA-256' },
    true, ['encrypt','decrypt']
  );
}

async function fingerprintOf(publicKeyJwk){
  const key = await crypto.subtle.importKey('jwk', publicKeyJwk, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['encrypt']);
  const spki = await crypto.subtle.exportKey('spki', key);
  const hash = await crypto.subtle.digest('SHA-256', spki);
  const hex = Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
  return hex.slice(0,20).toUpperCase().match(/.{1,4}/g).join(' ');
}

// encrypt arbitrary bytes for a list of recipient usernames -> {iv, ciphertext, keys:{user: wrappedB64}}
async function encryptForRecipients(bytes, recipientUsernames){
  const aesKey = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
  const rawAes = await crypto.subtle.exportKey('raw', aesKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, bytes);

  const keys = {};
  for (const uname of recipientUsernames){
    const entry = directory.find(d => d.username === uname) ||
                  (uname === session.username ? {publicKeyJwk: session.publicKeyJwk} : null);
    if (!entry) continue;
    const pub = await crypto.subtle.importKey('jwk', entry.publicKeyJwk, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['encrypt']);
    const wrapped = await crypto.subtle.encrypt({name:'RSA-OAEP'}, pub, rawAes);
    keys[uname] = buf2b64(wrapped);
  }
  return { iv: buf2b64(iv), ciphertext: buf2b64(ciphertext), keys };
}

async function decryptMessage(msg){
  const wrapped = msg.keys[session.username];
  if (!wrapped) throw new Error('no key for this account');
  const rawAes = await crypto.subtle.decrypt({name:'RSA-OAEP'}, session.privateKey, b642buf(wrapped));
  const aesKey = await crypto.subtle.importKey('raw', rawAes, {name:'AES-GCM'}, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: b642buf(msg.iv)}, aesKey, b642buf(msg.ciphertext));
  return plain;
}
