
const express = require('express');
const http = require('http');
const path = require('path');
const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  reconnectionAttempts: 5
});
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Security & middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Rate limiting (simple in-memory implementation)
const rateLimits = new Map();
function rateLimit(req, res, next, limit = 30, window = 60000) {
  const ip = req.ip;
  const now = Date.now();
  const key = `${ip}:${Math.floor(now / window)}`;
  
  if (!rateLimits.has(key)) {
    rateLimits.set(key, 0);
  }
  
  const count = rateLimits.get(key);
  if (count >= limit) {
    return res.status(429).json({ error: 'Too many requests. Please wait.' });
  }
  
  rateLimits.set(key, count + 1);
  
  // Cleanup old keys
  if (Math.random() < 0.01) {
    for (const [k] of rateLimits) {
      if (!k.startsWith(ip)) {
        rateLimits.delete(k);
      }
    }
  }
  
  next();
}

// Input sanitization
function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input
    .trim()
    .slice(0, 500) // Limit length
    .replace(/[<>]/g, '') // Remove angle brackets
    .replace(/javascript:/gi, ''); // Remove javascript protocol
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
const adminSetupKey = process.env.ADMIN_SETUP_KEY || 'admin-secret-setup-key';

// DB setup
const dbFile = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbFile);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at INTEGER,
    last_login INTEGER
  )`);
  db.all(`PRAGMA table_info(accounts)`, (err, columns) => {
    if (columns && !columns.some(col => col.name === 'is_admin')) {
      db.run(`ALTER TABLE accounts ADD COLUMN is_admin INTEGER DEFAULT 0`);
    }
    if (columns && !columns.some(col => col.name === 'last_login')) {
      db.run(`ALTER TABLE accounts ADD COLUMN last_login INTEGER`);
    }
  });
  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    socket_id TEXT,
    status TEXT DEFAULT 'online'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT,
    from_user TEXT,
    to_user TEXT,
    msg TEXT,
    ts INTEGER,
    edited_at INTEGER,
    read_at INTEGER
  )`);
  db.all(`PRAGMA table_info(messages)`, (err, columns) => {
    if (columns && !columns.some(col => col.name === 'read_at')) {
      db.run(`ALTER TABLE messages ADD COLUMN read_at INTEGER`);
    }
  });
});

const usernameToSocket = new Map();
const socketToUsername = new Map();
const userIdToSocket = new Map();
const socketToUserId = new Map();
const socketToEmail = new Map();

// Auth endpoints
app.post('/register', rateLimit, async (req, res) => {
  try {
    const { email, displayName, password } = req.body;
    if (!email || !displayName || !password || !validateEmail(email) || password.length < 6) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const sanitizedName = sanitizeInput(displayName);
    if (!sanitizedName) {
      return res.status(400).json({ error: 'Invalid display name' });
    }
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO accounts(email, display_name, password_hash, created_at) VALUES(?, ?, ?, ?)', [email.toLowerCase(), sanitizedName, hash, Date.now()], function(err) {
      if (err) {
        return res.status(err.message.includes('UNIQUE') ? 409 : 500).json({ error: 'Registration failed' });
      }
      const token = jwt.sign({ email: email.toLowerCase(), displayName: sanitizedName, id: this.lastID, isAdmin: false }, jwtSecret, { expiresIn: '7d' });
      res.json({ ok: true, token, email: email.toLowerCase(), displayName: sanitizedName, isAdmin: false, id: this.lastID });
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', rateLimit, (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || !validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    db.get('SELECT id, email, display_name, password_hash, is_admin FROM accounts WHERE email = ?', [email.toLowerCase()], async (err, row) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      if (!row) return res.status(401).json({ error: 'Email not found' });
      const match = await bcrypt.compare(password, row.password_hash);
      if (!match) return res.status(401).json({ error: 'Incorrect password' });
      db.run('UPDATE accounts SET last_login = ? WHERE id = ?', [Date.now(), row.id]);
      const token = jwt.sign({ email: row.email, displayName: row.display_name, id: row.id, isAdmin: row.is_admin }, jwtSecret, { expiresIn: '7d' });
      res.json({ ok: true, token, email: row.email, displayName: row.display_name, isAdmin: row.is_admin, id: row.id });
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, jwtSecret);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/users', verifyToken, (req, res) => {
    db.all('SELECT id, display_name FROM accounts', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        const users = rows.map(row => ({
            id: row.id,
            displayName: row.display_name,
            isOnline: userIdToSocket.has(row.id)
        }));
        res.json(users);
    });
});

app.get('/history/:room', (req, res) => {
  const room = req.params.room;
  db.all('SELECT id, room, from_user, to_user, msg, ts, read_at FROM messages WHERE room = ? ORDER BY ts ASC LIMIT 200', [room], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows || []);
  });
});

app.get('/history/private/:otherUserId', verifyToken, (req, res) => {
    const { otherUserId } = req.params;
    const requesterId = req.user.id;
    
    db.all('SELECT display_name FROM accounts WHERE id IN (?, ?)', [requesterId, otherUserId], (err, users) => {
        if (err || users.length < 2) return res.status(500).json({ error: 'DB error or user not found' });
        const requesterName = users.find(u => u.id == requesterId).display_name;
        const otherUserName = users.find(u => u.id == otherUserId).display_name;

        db.all(`SELECT id, from_user, to_user, msg, ts, read_at
                FROM messages
                WHERE room IS NULL AND ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?))
                ORDER BY ts ASC LIMIT 200`,
                [requesterName, otherUserName, otherUserName, requesterName], (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(rows || []);
        });
    });
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, jwtSecret);
    next();
  } catch (e) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const { email, displayName, id: userId } = socket.user;
  socketToEmail.set(socket.id, email);
  userIdToSocket.set(userId, socket.id);
  socketToUserId.set(socket.id, userId);
  io.emit('user status', { userId, status: 'online' });

  socket.on('set username', (username, ack) => {
    if (!username || typeof username !== 'string' || !username.trim()) {
        return ack && ack({ ok: false, error: 'Invalid username' });
    }
    username = username.trim();
    socketToUsername.set(socket.id, username);
    usernameToSocket.set(username, socket.id);
    ack && ack({ ok: true });
  });

  socket.on('create or join', (room, ack) => {
    socket.join(room);
    socket.to(room).emit('system message', `${socketToUsername.get(socket.id) || 'Someone'} joined ${room}`);
    ack && ack({ ok: true });
  });

  socket.on('leave room', (room) => {
    socket.leave(room);
    socket.to(room).emit('system message', `${socketToUsername.get(socket.id) || 'Someone'} left ${room}`);
  });

  socket.on('typing', (data) => {
    socket.to(data.room).emit('typing', data);
  });

  socket.on('chat message', (payload) => {
    const from = socketToUsername.get(socket.id) || displayName || 'Anonymous';
    const ts = Date.now();
    const msg = sanitizeInput(payload.msg);
    if (!msg || msg.length > 500) {
      return socket.emit('system message', '❌ Invalid message');
    }

    if (payload.to) { // 'to' is recipient's userId
      const toUserId = payload.to;
      const targetSocketId = userIdToSocket.get(toUserId);
      db.get('SELECT display_name FROM accounts WHERE id = ?', [toUserId], (err, user) => {
          if (err || !user) {
              return socket.emit('system message', '❌ Recipient not found.');
          }
          const toDisplayName = user.display_name;
          db.run('INSERT INTO messages(from_user, to_user, msg, ts) VALUES(?,?,?,?)', [from, toDisplayName, msg, ts], function(err) {
            if (err) return console.error('Message save error:', err);
            const messageId = this.lastID;
            if (targetSocketId) {
              io.to(targetSocketId).emit('private message', { id: messageId, from, msg, ts, to: toDisplayName });
            }
            socket.emit('private message', { id: messageId, from, msg, ts, to: toDisplayName, delivered: !!targetSocketId });
          });
      });
    } else if (payload.room) {
      db.run('INSERT INTO messages(room, from_user, msg, ts) VALUES(?,?,?,?)', [payload.room, from, msg, ts], function(err) {
        if (err) return console.error('Message save error:', err);
        io.to(payload.room).emit('chat message', { from, msg, room: payload.room, ts, id: this.lastID });
      });
    }
  });

  socket.on('disconnect', () => {
    const uId = socketToUserId.get(socket.id);
    if (uId) {
        userIdToSocket.delete(uId);
        io.emit('user status', { userId: uId, status: 'offline' });
    }
    socketToUserId.delete(socket.id);
    const username = socketToUsername.get(socket.id);
    if (username) usernameToSocket.delete(username);
    socketToUsername.delete(socket.id);
    socketToEmail.delete(socket.id);
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
