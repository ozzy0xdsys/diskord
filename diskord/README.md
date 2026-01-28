# Diskord

A lightweight session-based chat with **client-side E2EE** (AES‑GCM) and **ephemeral sessions**.

- **Login / Sign up on one page**: If a username doesn't exist, it is created with that password.
- **Sessions**: Create a session to get a shareable code like `ABCD-EFGH`. Join via code.
- **WebSockets**: Members receive real-time join/leave/message events.
- **Ephemeral**: When the owner ends a session, the server deletes all stored encrypted messages/files for that code and disconnects everyone.
- **E2EE**: The server stores only encrypted payloads. Clients derive a key from the session code.

> Security note: In this simple version, the **session code is the shared secret**. Anyone with the code can decrypt the chat. For stronger security, add an extra per-session passphrase prompt and derive from that instead.

## Local dev

```bash
npm install
npm start
# open http://localhost:3000
```

## Environment

- `PORT` (default 3000)
- `DATA_DIR` (default ./data)
- `DB_PATH` (default $DATA_DIR/diskord.sqlite)
