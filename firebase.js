const FirebaseStore = {
  async getJSON(key){
    try{
      const res = await withTimeout(fetch(APP_CONFIG.FIREBASE_DB_URL + '/' + keyToPath(key) + '.json'), APP_CONFIG.STORAGE_TIMEOUT_MS, 'Reading "' + key + '"');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return await res.json();
    } catch (e) {
      logDebug('getJSON failed', key, e.message);
      return null;
    }
  },

  async putJSON(key, value){
    const res = await withTimeout(fetch(APP_CONFIG.FIREBASE_DB_URL + '/' + keyToPath(key) + '.json', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value)
    }), APP_CONFIG.STORAGE_TIMEOUT_MS, 'Writing "' + key + '"');
    if (!res.ok) throw new Error('The database rejected that save (HTTP ' + res.status + ').');
    return await res.json();
  },

  async patchJSON(key, value){
    const res = await withTimeout(fetch(APP_CONFIG.FIREBASE_DB_URL + '/' + keyToPath(key) + '.json', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value)
    }), APP_CONFIG.STORAGE_TIMEOUT_MS, 'Updating "' + key + '"');
    if (!res.ok) throw new Error('The database rejected that update (HTTP ' + res.status + ').');
    return await res.json();
  },

  async deleteJSON(key){
    const res = await withTimeout(fetch(APP_CONFIG.FIREBASE_DB_URL + '/' + keyToPath(key) + '.json', {
      method: 'DELETE'
    }), APP_CONFIG.STORAGE_TIMEOUT_MS, 'Deleting "' + key + '"');
    if (!res.ok) throw new Error('The database rejected that delete (HTTP ' + res.status + ').');
    return await res.json();
  },

  async setJSON(key, value){
    return this.putJSON(key, value);
  }
};
