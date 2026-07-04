/* ============================================================================
   config.js — the one file you edit per deployment.
   Loaded first, before anything else, so every other file can rely on these
   constants already existing.
   ========================================================================= */

/* ── Backend configuration ──────────────────────────────────────────────
   This app needs ONE small always-on database so that different people's
   browsers can see the same accounts/messages. Claude's own storage bridge
   (window.storage) only exists inside Claude's chat window — it does not
   exist on a GitHub Pages URL, because GitHub Pages is 100% static hosting
   with no backend of its own. So instead we talk directly to Firebase's
   free Realtime Database over plain HTTPS (no SDK, just fetch calls) —
   that's a real, independent, always-on service GitHub Pages CAN reach.

   To activate this:
   1. Go to https://console.firebase.google.com -> Add project (free).
   2. In your project, open "Build -> Realtime Database" -> Create Database
      -> start in TEST MODE (open read/write; fine here since every message
      is already end-to-end encrypted before it ever reaches this database —
      it only ever stores ciphertext).
   3. Copy the Database URL (looks like https://YOUR-PROJECT-default-rtdb
      .firebaseio.com or ...asia-southeast1.firebasedatabase.app) and paste
      it below, replacing the current value.

   Honest tradeoff: "test mode" rules mean anyone with this URL could also
   write or delete data (they still can't read message content — it's
   ciphertext). Fine for a small friend group; ask if you want it locked
   down further later with Firebase Authentication.

   Heads up: Firebase test-mode rules usually expire ~30 days after
   creation. If writes suddenly start failing after a month, that's why —
   go to Realtime Database -> Rules in the Firebase console and extend it.
   ------------------------------------------------------------------------ */
const FIREBASE_DB_URL = "https://encrypted-chat-9d7ed-default-rtdb.asia-southeast1.firebasedatabase.app";

const BACKEND_CONFIGURED = typeof FIREBASE_DB_URL === 'string'
  && FIREBASE_DB_URL.startsWith('https://')
  && !FIREBASE_DB_URL.includes('PASTE_YOUR');

// How long a single database read/write is allowed to hang before we give up
// and show an error, instead of leaving the UI frozen with no feedback.
const STORAGE_TIMEOUT_MS = 8000;

// A message is deleted for everyone this long after the first person saves
// or downloads it (see markSaved() in app.js).
const AUTO_DELETE_MS = 30 * 60 * 1000; // 30 minutes
