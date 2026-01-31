# Diskord (simplified)

A minimal dark-mode chat app with:
- Register + login (passwords hashed)
- Session codes (XXXX-XXXX) to create or join
- WebSockets for join/leave/messages/files
- Client-side encryption (AES-GCM via Web Crypto). The server only relays ciphertext.
- Ending a session deletes it server-side (no message/file persistence).

## Run locally
```bash
npm install
npm start
# open http://localhost:3000
```
