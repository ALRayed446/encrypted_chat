const CryptoStore = {
  async deriveWrapKey(password, saltBytes){
    const baseKey = await crypto.subtle.importKey('raw', strToBuf(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: APP_CONFIG.PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async generateKeypair(){
    return crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: APP_CONFIG.RSA_MODULUS_LENGTH, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
  },

  async fingerprintOf(publicKeyJwk){
    const key = await crypto.subtle.importKey('jwk', publicKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    const spki = await crypto.subtle.exportKey('spki', key);
    const hash = await crypto.subtle.digest('SHA-256', spki);
    const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex.slice(0, 20).toUpperCase().match(/.{1,4}/g).join(' ');
  },

  async encryptForRecipients(bytes, recipientUsernames){
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const rawAes = await crypto.subtle.exportKey('raw', aesKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, bytes);

    const keys = {};
    for (const uname of recipientUsernames){
      const entry = state.directory.find(d => d.username === uname) || (uname === state.session.username ? { publicKeyJwk: state.session.publicKeyJwk } : null);
      if (!entry || !entry.publicKeyJwk) continue;
      const pub = await crypto.subtle.importKey('jwk', entry.publicKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
      const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawAes);
      keys[uname] = buf2b64(wrapped);
    }

    return { iv: buf2b64(iv), ciphertext: buf2b64(ciphertext), keys };
  },

  async decryptMessage(msg){
    const wrapped = msg.keys[state.session.username];
    if (!wrapped) throw new Error('no key for this account');
    const rawAes = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, state.session.privateKey, b642buf(wrapped));
    const aesKey = await crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b642buf(msg.iv) }, aesKey, b642buf(msg.ciphertext));
  }
};
