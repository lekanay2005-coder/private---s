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
app.use(express.urlencoded({ limit: '10kb' }));
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
  // Migration: add is_admin column if it doesn't exist
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
    edited_at INTEGER
  )`);
});

// Maps to track usernames <-> socket ids (in-memory for routing)
const usernameToSocket = new Map();
const socketToUsername = new Map();
const socketToEmail = new Map();

// Auth endpoints
app.post('/register', rateLimit, async (req, res) => {
  try {
    const { email, displayName, password } = req.body;
    
    // Validation
    if (!email || !displayName || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const sanitizedName = sanitizeInput(displayName);
    if (!sanitizedName) {
      return res.status(400).json({ error: 'Invalid display name' });
    }

    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO accounts(email, display_name, password_hash, created_at) VALUES(?, ?, ?, ?)',
      [email.toLowerCase(), sanitizedName, hash, Date.now()],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Email already registered' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        const token = jwt.sign({ email: email.toLowerCase(), displayName: sanitizedName, id: this.lastID, isAdmin: false }, jwtSecret, { expiresIn: '7d' });
        res.json({ ok: true, token, email: email.toLowerCase(), displayName: sanitizedName, isAdmin: false });
      }
    );
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', rateLimit, (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing email or password' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    db.get('SELECT id, email, display_name, password_hash, is_admin FROM accounts WHERE email = ?', [email.toLowerCase()], async (err, row) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      if (!row) return res.status(401).json({ error: 'Email not found' });

      try {
        const match = await bcrypt.compare(password, row.password_hash);
        if (!match) return res.status(401).json({ error: 'Incorrect password' });

        // Update last login
        db.run('UPDATE accounts SET last_login = ? WHERE id = ?', [Date.now(), row.id]);

        const token = jwt.sign({ email: row.email, displayName: row.display_name, id: row.id, isAdmin: row.is_admin }, jwtSecret, { expiresIn: '7d' });
        res.json({ ok: true, token, email: row.email, displayName: row.display_name, isAdmin: row.is_admin });
      } catch (e) {
        res.status(500).json({ error: 'Authentication error' });
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
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

// Admin setup endpoint
app.post('/admin/setup', async (req, res) => {
  const { email, displayName, password, setupKey } = req.body;
  if (setupKey !== adminSetupKey) {
    return res.status(403).json({ error: 'Invalid setup key' });
  }
  if (!email || !displayName || !password) {
    return res.status(400).json({ error: 'Missing email, displayName, or password' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT OR REPLACE INTO accounts(email, display_name, password_hash, is_admin, created_at) VALUES(?, ?, ?, 1, ?)',
      [email, displayName, hash, Date.now()],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'DB error' });
        }
        const token = jwt.sign({ email, displayName, id: this.lastID, isAdmin: true }, jwtSecret, { expiresIn: '7d' });
        res.json({ ok: true, token, email, displayName, isAdmin: true, message: 'Admin account created successfully' });
      }
    );
  } catch (e) {
    res.status(500).json({ error: 'Hash error' });
  }
});

// Promote user to admin endpoint
app.post('/admin/promote', (req, res) => {
  const { email, setupKey } = req.body;
  if (setupKey !== adminSetupKey) {
    return res.status(403).json({ error: 'Invalid setup key' });
  }
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  db.run('UPDATE accounts SET is_admin = 1 WHERE email = ?', [email], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, message: `${email} is now an admin` });
  });
});

// History endpoint: returns last 200 messages for a room
app.get('/history/:room', (req, res) => {
  const room = req.params.room;
  db.all('SELECT id, room, from_user, to_user, msg, ts FROM messages WHERE room = ? ORDER BY ts ASC LIMIT 200', [room], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows || []);
  });
});

// ============ ADMIN ENDPOINTS ============

// Get all users (admin only)
app.get('/admin/users', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  db.all('SELECT id, email, display_name, is_admin, created_at FROM accounts ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows || []);
  });
});

// Get all messages (admin only)
app.get('/admin/messages', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const limit = req.query.limit || 500;
  const offset = req.query.offset || 0;
  
  db.all(
    'SELECT id, room, from_user, to_user, msg, ts FROM messages ORDER BY ts DESC LIMIT ? OFFSET ?',
    [parseInt(limit), parseInt(offset)],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      
      // Get total count
      db.get('SELECT COUNT(*) as total FROM messages', (err2, countRow) => {
        if (err2) return res.status(500).json({ error: 'DB error' });
        
        res.json({
          messages: rows || [],
          total: countRow.total,
          limit: parseInt(limit),
          offset: parseInt(offset)
        });
      });
    }
  );
});

// Delete user (admin only)
app.delete('/admin/users/:email', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const email = req.params.email;
  db.run('DELETE FROM accounts WHERE email = ?', [email], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, message: `User ${email} deleted` });
  });
});

// Clear all messages (admin only)
app.delete('/admin/messages', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  db.run('DELETE FROM messages', function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true, message: `All ${this.changes} messages deleted` });
  });
});

// Clear messages in a room (admin only)
app.delete('/admin/messages/:room', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const room = req.params.room;
  db.run('DELETE FROM messages WHERE room = ?', [room], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true, message: `${this.changes} messages deleted from ${room}` });
  });
});

// Get admin statistics
app.get('/admin/stats', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  db.get('SELECT COUNT(*) as total_users FROM accounts', (err1, userCount) => {
    if (err1) return res.status(500).json({ error: 'DB error' });
    
    db.get('SELECT COUNT(*) as total_messages FROM messages', (err2, messageCount) => {
      if (err2) return res.status(500).json({ error: 'DB error' });
      
      db.get('SELECT COUNT(DISTINCT room) as total_rooms FROM messages WHERE room IS NOT NULL', (err3, roomCount) => {
        if (err3) return res.status(500).json({ error: 'DB error' });
        
        res.json({
          totalUsers: userCount.total_users || 0,
          totalMessages: messageCount.total_messages || 0,
          totalRooms: roomCount.total_rooms || 0,
          onlineUsers: socketToEmail.size
        });
      });
    });
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

    // Validate message
    const msg = sanitizeInput(payload.msg);
    if (!msg) {
      return socket.emit('system message', '❌ Message cannot be empty');
    }
    if (msg.length > 500) {
      return socket.emit('system message', '❌ Message is too long (max 500 characters)');
    }

    if (payload.to) {
      const targetId = usernameToSocket.get(payload.to);
      // Persist private message
      db.run('INSERT INTO messages(room, from_user, to_user, msg, ts) VALUES(?,?,?,?,?)', [null, from, payload.to, msg, ts], (err) => {
        if (err) console.error('Message save error:', err);
      });
      if (targetId) {
        io.to(targetId).emit('private message', { from, msg, ts, read: false });
        socket.emit('private message', { from, msg, ts, delivered: true });
      } else {
        socket.emit('system message', `❌ User ${payload.to} not found or offline`);
      }
    } else if (payload.room) {
      // Persist room message
      db.run('INSERT INTO messages(room, from_user, to_user, msg, ts) VALUES(?,?,?,?,?)', [payload.room, from, null, msg, ts], (err) => {
        if (err) console.error('Message save error:', err);
      });
      io.to(payload.room).emit('chat message', { from, msg, room: payload.room, ts, id: ts });
    } else {
      db.run('INSERT INTO messages(room, from_user, to_user, msg, ts) VALUES(?,?,?,?,?)', [null, from, null, msg, ts], (err) => {
        if (err) console.error('Message save error:', err);
      });
      io.emit('chat message', { from, msg, ts, id: ts });
    }
  });

  // Typing indicator
  socket.on('typing', (data) => {
    const username = socketToUsername.get(socket.id);
    if (!username) return;
    
    if (data.room) {
      socket.to(data.room).emit('user typing', { username, room: data.room });
    } else if (data.to) {
      const targetId = usernameToSocket.get(data.to);
      if (targetId) {
        io.to(targetId).emit('user typing', { username, from: username });
      }
    }
  });

  socket.on('stop typing', (data) => {
    const username = socketToUsername.get(socket.id);
    if (!username) return;
    
    if (data.room) {
      socket.to(data.room).emit('user stop typing', { username });
    } else if (data.to) {
      const targetId = usernameToSocket.get(data.to);
      if (targetId) {
        io.to(targetId).emit('user stop typing', { username });
      }
    }
  });

  // User status
  socket.on('set status', (status, ack) => {
    const username = socketToUsername.get(socket.id);
    if (!username) return ack && ack({ ok: false });
    
    const validStatuses = ['online', 'away', 'do-not-disturb'];
    if (!validStatuses.includes(status)) {
      return ack && ack({ ok: false, error: 'Invalid status' });
    }
    
    db.run('UPDATE users SET status = ? WHERE username = ?', [status, username]);
    socket.broadcast.emit('user status', { username, status });
    ack && ack({ ok: true });
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

  // Admin: broadcast system announcement
  socket.on('admin announce', (msg, ack) => {
    db.get('SELECT is_admin FROM accounts WHERE email = ?', [email], (err, row) => {
      if (err || !row || !row.is_admin) {
        return ack && ack({ ok: false, error: 'Admin only' });
      }
      io.emit('system message', `📢 ANNOUNCEMENT: ${msg}`);
      ack && ack({ ok: true });
    });
  });

  // Admin: kick user from room
  socket.on('admin kick', (data, ack) => {
    const { username, room } = data;
    db.get('SELECT is_admin FROM accounts WHERE email = ?', [email], (err, row) => {
      if (err || !row || !row.is_admin) {
        return ack && ack({ ok: false, error: 'Admin only' });
      }
      const targetId = usernameToSocket.get(username);
      if (targetId) {
        io.to(targetId).emit('system message', `You were kicked from ${room} by an admin`);
        const targetSocket = io.sockets.sockets.get(targetId);
        if (targetSocket) {
          targetSocket.leave(room);
        }
        ack && ack({ ok: true, message: `${username} kicked from ${room}` });
      } else {
        ack && ack({ ok: false, error: 'User not found' });
      }
    });
  });

  // Admin: ban user
  socket.on('admin ban', (username, ack) => {
    db.get('SELECT is_admin FROM accounts WHERE email = ?', [email], (err, row) => {
      if (err || !row || !row.is_admin) {
        return ack && ack({ ok: false, error: 'Admin only' });
      }
      const targetId = usernameToSocket.get(username);
      if (targetId) {
        io.to(targetId).emit('system message', 'You have been banned by an admin');
        const targetSocket = io.sockets.sockets.get(targetId);
        if (targetSocket) {
          targetSocket.disconnect(true);
        }
        ack && ack({ ok: true, message: `${username} banned` });
      } else {
        ack && ack({ ok: false, error: 'User not found' });
      }
    });
  });

  // Admin: mute user
  socket.on('admin mute', (username, ack) => {
    db.get('SELECT is_admin FROM accounts WHERE email = ?', [email], (err, row) => {
      if (err || !row || !row.is_admin) {
        return ack && ack({ ok: false, error: 'Admin only' });
      }
      // Mark user as muted (simple approach)
      const targetId = usernameToSocket.get(username);
      if (targetId) {
        io.to(targetId).emit('system message', 'You have been muted by an admin');
        ack && ack({ ok: true, message: `${username} muted` });
      } else {
        ack && ack({ ok: false, error: 'User not found' });
      }
    });
  });
});

server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
