const express = require('express');
const http = require('http');
const path = require('path');
const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';

// DB setup
const dbFile = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbFile);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    socket_id TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT,
    from_user TEXT,
    to_user TEXT,
    msg TEXT,
    ts INTEGER
  )`);
});

// Maps to track usernames <-> socket ids (in-memory for routing)
const usernameToSocket = new Map();
const socketToUsername = new Map();
const socketToEmail = new Map();

// Auth endpoints
app.post('/register', async (req, res) => {
  const { email, displayName, password } = req.body;
  if (!email || !displayName || !password) {
    return res.status(400).json({ error: 'Missing email, displayName, or password' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO accounts(email, display_name, password_hash, created_at) VALUES(?, ?, ?, ?)',
      [email, displayName, hash, Date.now()],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Email already registered' });
          }
          return res.status(500).json({ error: 'DB error' });
        }
        const token = jwt.sign({ email, displayName, id: this.lastID }, jwtSecret, { expiresIn: '7d' });
        res.json({ ok: true, token, email, displayName });
      }
    );
  } catch (e) {
    res.status(500).json({ error: 'Hash error' });
  }
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }

  db.get('SELECT id, email, display_name, password_hash FROM accounts WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(401).json({ error: 'Email not found' });

    try {
      const match = await bcrypt.compare(password, row.password_hash);
      if (!match) return res.status(401).json({ error: 'Incorrect password' });

      const token = jwt.sign({ email: row.email, displayName: row.display_name, id: row.id }, jwtSecret, { expiresIn: '7d' });
      res.json({ ok: true, token, email: row.email, displayName: row.display_name });
    } catch (e) {
      res.status(500).json({ error: 'Compare error' });
    }
  });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// History endpoint: returns last 200 messages for a room
app.get('/history/:room', (req, res) => {
  const room = req.params.room;
  db.all('SELECT id, room, from_user, to_user, msg, ts FROM messages WHERE room = ? ORDER BY ts ASC LIMIT 200', [room], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows || []);
  });
});

// Socket.io with JWT auth
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));

  try {
    const decoded = jwt.verify(token, jwtSecret);
    socket.user = decoded;
    next();
  } catch (e) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const email = socket.user.email;
  const displayName = socket.user.displayName;
  socketToEmail.set(socket.id, email);

  socket.on('set username', (username, ack) => {
    if (!username || typeof username !== 'string') return ack && ack({ ok: false, error: 'Invalid username' });
    username = username.trim();
    if (!username) return ack && ack({ ok: false, error: 'Invalid username' });

    // Check if username is already taken by another socket
    db.get('SELECT socket_id FROM users WHERE username = ?', [username], (err, row) => {
      if (err) return ack && ack({ ok: false, error: 'DB error' });
      if (row && row.socket_id && row.socket_id !== socket.id) {
        return ack && ack({ ok: false, error: 'Username already taken' });
      }

      // Save in DB and in-memory maps
      db.run('INSERT OR REPLACE INTO users(username, socket_id) VALUES(?, ?)', [username, socket.id], (err2) => {
        if (err2) return ack && ack({ ok: false, error: 'DB save failed' });
        socketToUsername.set(socket.id, username);
        usernameToSocket.set(username, socket.id);
        ack && ack({ ok: true });
      });
    });
  });

  socket.on('create or join', (room, ack) => {
    socket.join(room);
    socket.to(room).emit('system message', `${socketToUsername.get(socket.id) || 'Someone'} joined ${room}`);
    ack && ack({ ok: true });
  });

  socket.on('chat message', (payload) => {
    // payload: { room, msg, to }
    const from = socketToUsername.get(socket.id) || displayName || 'Anonymous';
    const ts = Date.now();

    if (payload.to) {
      const targetId = usernameToSocket.get(payload.to);
      // Persist private message
      db.run('INSERT INTO messages(room, from_user, to_user, msg, ts) VALUES(?,?,?,?,?)', [null, from, payload.to, payload.msg, ts]);
      if (targetId) {
        io.to(targetId).emit('private message', { from, msg: payload.msg, ts });
        socket.emit('private message', { from, msg: payload.msg, ts });
      } else {
        socket.emit('system message', `User ${payload.to} not found`);
      }
    } else if (payload.room) {
      // Persist room message
      db.run('INSERT INTO messages(room, from_user, to_user, msg, ts) VALUES(?,?,?,?,?)', [payload.room, from, null, payload.msg, ts]);
      io.to(payload.room).emit('chat message', { from, msg: payload.msg, room: payload.room, ts });
    } else {
      db.run('INSERT INTO messages(room, from_user, to_user, msg, ts) VALUES(?,?,?,?,?)', [null, from, null, payload.msg, ts]);
      io.emit('chat message', { from, msg: payload.msg, ts });
    }
  });

  socket.on('leave room', (room, ack) => {
    socket.leave(room);
    socket.to(room).emit('system message', `${socketToUsername.get(socket.id) || 'Someone'} left ${room}`);
    ack && ack({ ok: true });
  });

  socket.on('disconnect', () => {
    const username = socketToUsername.get(socket.id);
    if (username) {
      usernameToSocket.delete(username);
      db.run('DELETE FROM users WHERE username = ?', [username]);
    }
    socketToUsername.delete(socket.id);
    socketToEmail.delete(socket.id);
  });
});

server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
