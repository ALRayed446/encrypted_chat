/* ============================================================================
   firebase.js — talks to Firebase Realtime Database over plain HTTPS.
   No SDK, just fetch(). This is the ONLY file that knows the data lives in
   Firebase — everything else just calls getJSON/setJSON and doesn't care
   what's on the other end. Swapping backends later means editing only here.
   ========================================================================= */

// Firebase Realtime Database paths use "/" as a separator; our app keys use
// ":" (e.g. "account:rayed"). This just translates one into the other.
function keyToPath(key){ return key.replace(/:/g, '/'); }

async function getJSON(key, shared){
  try{
    const res = await withTimeout(fetch(FIREBASE_DB_URL + '/' + keyToPath(key) + '.json'), STORAGE_TIMEOUT_MS, 'Reading "'+key+'"');
    if (!res.ok) return null;
    return await res.json(); // Firebase returns JSON `null` for a path that doesn't exist yet
  }catch(e){ return null; }
}

async function setJSON(key, value, shared){
  let res;
  try{
    res = await withTimeout(fetch(FIREBASE_DB_URL + '/' + keyToPath(key) + '.json', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value)
    }), STORAGE_TIMEOUT_MS, 'Saving "'+key+'"');
  }catch(e){
    throw new Error(e.message && e.message.includes('timed out') ? e.message : 'Network error while saving — ' + (e.message || 'request failed') + '. Check your connection and try again.');
  }
  if (!res.ok){
    throw new Error('The database rejected that save (HTTP ' + res.status + '). If you just set this up, double-check the Realtime Database rules allow writes.');
  }
  return await res.json();
}
