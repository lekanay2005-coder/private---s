# Fun Chat

Fun Chat — minimal chat application using Express + Socket.io. Supports:
- Setting a username
- Creating/joining rooms (groups)
- Sending messages to rooms
- Sending private messages to a username

Quick start:

```bash
cd chat
npm install
npm start
# open http://localhost:3000
```

Important notes / defaults implemented by the helper:
- Username uniqueness is enforced (server will reject a taken name).
- Messages are persisted to a local SQLite database `chat.db`.
- When you join a room the last messages for that room are returned.

Fill-in items you should consider next:
- Add real authentication (JWT/OAuth) if you need secure accounts.
- Use Redis adapter and a production DB when scaling across nodes.
- Configure TLS and a domain for public deployment.
