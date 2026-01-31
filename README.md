# Diskord

A minimal dark-mode chat app with:

- Register + login (passwords hashed)
- Multiple sessions at once (switch like Discord)
- Leave sessions
- Auto-rejoin on refresh (with a short disconnect grace period so you don’t immediately appear to leave)
- WebSockets for presence/messages/files
- Client-side encryption (AES-GCM via Web Crypto). The server only relays ciphertext.
- Ending a session deletes it server-side (no message/file persistence).
- Settings: profile picture + password change

## Run locally
```bash
npm install
npm start
# open http://localhost:3000
```
