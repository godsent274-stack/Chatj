const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- Database setup ---
const db = new Database(path.join(__dirname, 'chat.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(room_id) REFERENCES rooms(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// Seed a default room if none exist
const generalRoom = db.prepare('SELECT * FROM rooms WHERE name = ?').get('general');
if (!generalRoom) {
  db.prepare('INSERT INTO rooms (id, name) VALUES (?, ?)').run(uuidv4(), 'general');
}

// --- Session (shared between Express and Socket.io) ---
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    secure: process.env.NODE_ENV === 'production'
  }
});

app.use(sessionMiddleware);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// --- Auth routes ---
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Username must be 3+ characters, password 6+ characters' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(id, username, hash);
  req.session.userId = id;
  req.session.username = username;
  res.json({ id, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ id: user.id, username: user.username });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  res.json({ id: req.session.userId, username: req.session.username });
});

// --- Rooms ---
app.get('/api/rooms', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM rooms ORDER BY name').all());
});

app.post('/api/rooms', requireAuth, (req, res) => {
  const { name } = req.body || {};
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Room name too short' });
  const clean = name.trim().slice(0, 40);
  const existing = db.prepare('SELECT id FROM rooms WHERE name = ?').get(clean);
  if (existing) return res.status(400).json({ error: 'Room already exists' });
  const id = uuidv4();
  db.prepare('INSERT INTO rooms (id, name) VALUES (?, ?)').run(id, clean);
  res.json({ id, name: clean });
});

app.get('/api/rooms/:roomId/messages', requireAuth, (req, res) => {
  const msgs = db.prepare(
    'SELECT * FROM messages WHERE room_id = ? ORDER BY created_at ASC LIMIT 100'
  ).all(req.params.roomId);
  res.json(msgs);
});

// --- Socket.io wired to the same session store ---
io.engine.use(sessionMiddleware);

io.on('connection', (socket) => {
  const sess = socket.request.session;
  if (!sess || !sess.userId) {
    socket.disconnect();
    return;
  }

  socket.on('join_room', (roomId) => {
    if (typeof roomId === 'string') socket.join(roomId);
  });

  socket.on('leave_room', (roomId) => {
    if (typeof roomId === 'string') socket.leave(roomId);
  });

  socket.on('send_message', ({ roomId, body } = {}) => {
    if (!roomId || !body || !body.trim()) return;
    const id = uuidv4();
    const trimmed = body.trim().slice(0, 2000);

    db.prepare(
      'INSERT INTO messages (id, room_id, user_id, username, body) VALUES (?, ?, ?, ?, ?)'
    ).run(id, roomId, sess.userId, sess.username, trimmed);

    io.to(roomId).emit('new_message', {
      id,
      room_id: roomId,
      user_id: sess.userId,
      username: sess.username,
      body: trimmed,
      created_at: new Date().toISOString()
    });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Chat server running on port ${PORT}`));
