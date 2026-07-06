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

// ── Retention & account lifecycle ──────────────────────────────────────
// User-selectable options for "how long should conversation history stick
// around" (Settings -> Retention). Applied per-conversation as the SHORTEST
// setting among everyone in that conversation — nobody's stricter privacy
// preference gets overridden by someone else's looser one.
const RETENTION_OPTIONS_DAYS = [3, 7, 15, 30];
const DEFAULT_RETENTION_DAYS = 30;

// If a conversation's soonest-to-expire message is within this window,
// show a "these will be deleted soon" banner (see getRetentionWarning() in app.js).
const RETENTION_WARNING_MS = 24 * 60 * 60 * 1000; // 24 hours

// Account expiry: if nobody logs in for this long, the account is swept up
// the next time ANY logged-in user's browser happens to run the check
// (see runAccountExpirySweep() in app.js). There's no real server here, so
// this is best-effort, not a guaranteed-timing background job.
const ACCOUNT_EXPIRY_DAYS = 3;
const ACCOUNT_EXPIRY_MS = ACCOUNT_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
