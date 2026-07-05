# 🔒 Sealed — Private End-to-End Encrypted Chat

[![Live Demo](https://img.shields.io/badge/Live_Demo-GitHub_Pages-00FF9C?style=for-the-badge&logo=githubpages)](https://alrayed446.github.io/encrypted_chat/)
[![Firebase](https://img.shields.io/badge/Firebase-Realtime_Database-FFCA28?style=for-the-badge&logo=firebase)](https://firebase.google.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**Sealed** is a secure, private, end-to-end encrypted messaging application.  
It runs entirely in your browser, stores nothing on the server, and uses military-grade encryption to keep your conversations safe.

> **Your messages are sealed to the intended recipient – and only they can unlock them.**

---

## 🚀 Live Demo

Try it now: **[https://alrayed446.github.io/encrypted_chat/](https://alrayed446.github.io/encrypted_chat/)**

---

## ✨ Features

### 🔐 Security & Privacy
- **End-to-End Encryption** – RSA‑OAEP (2048-bit) + AES‑256‑GCM.  
- **Zero-knowledge architecture** – your private key is *never* stored on the server; only the password-encrypted version is saved.  
- **Password-derived key** (PBKDF2, 250,000 rounds) to unlock your private key.  
- **"Safety Code"** (fingerprint) to verify contacts out-of-band.  
- **Privacy Mode** – blurs messages when you switch tabs or windows (prevents screen peeking).

### 💬 Chat Features
- **1-on-1 Private Chats** & **Groups**.  
- **Reply to Messages** – just like WhatsApp/Signal. Click the ↩️ icon on any message, type your reply, and the quoted text appears in your bubble.  
- **Message Reactions** – hover over a message and pick 👍 ❤️ 😂 😮 😢 🙏.  
- **Read Receipts** – see if your message was Delivered or Seen.  
- **Typing Indicator** – know when the other person is typing.  
- **Disappearing Messages** – choose a timer (1m, 5m, 30m, 1h, 24h) before sending. Messages auto‑delete from the server after the timer expires.  
- **File & Image Sharing** – send images and files (up to 3MB) securely.  
- **Save Messages** – keep messages beyond the auto‑delete window by clicking "Save".

### 👤 User Experience
- **Persistent Login ("Remember Me")** – stay logged in across sessions.  
- **Profile Pictures** – upload your own avatar (click the ✎ icon on your avatar).  
- **Online / Last Seen** – shows live presence status in private chats.  
- **Search Contacts** – find users quickly when starting a new chat.  
- **Block System** – **Hard Block** (immediate cut-off) or **Soft Block** (allows one final message).  
- **Responsive Design** – works on desktop, tablet, and mobile.

---

## 🧠 How the Encryption Works (The "Magic" Explained)

Think of **Sealed** like a digital safe that only you and your friend have the key to.  

1. **Every account** generates a **RSA‑2048 keypair** in your browser (using Web Crypto API).  
2. The **public key** is stored openly on Firebase (that’s the point of public keys).  
3. The **private key** is **encrypted** with a key derived *from your password* (PBKDF2) before it is ever uploaded. **Your password is never sent anywhere.**  
4. When you send a message:  
   - The app generates a **fresh AES‑256‑GCM key** for that message *only*.  
   - It encrypts the message content with that AES key.  
   - It then wraps (RSA‑encrypts) that AES key individually for **each recipient's public key**.  
5. The server (Firebase) only stores:  
   - The encrypted message body.  
   - A list of wrapped AES keys (one per recipient).  
   - Metadata (timestamp, sender, etc.) which is **not encrypted** to allow the app to show your inbox (this is a conscious trade‑off for performance).  

**Result:** Even if someone steals your Firebase database, they see only ciphertext. Without your private key (unlocked by your password), the messages are unreadable.

---

## 🛠️ Tech Stack

| Technology | Purpose |
| :--- | :--- |
| **HTML5 + CSS3** | Structure and styling (Dark, Terminal‑inspired UI). |
| **Vanilla JavaScript** | All logic, rendering, and encryption (no frameworks needed). |
| **Firebase Realtime Database** | Backend storage (accounts, messages, typing states). |
| **Web Crypto API** | RSA‑OAEP, AES‑GCM, PBKDF2 – all built into the browser. |
| **GitHub Pages** | Free, static hosting. |

---

## 🗂️ Project Structure
