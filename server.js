const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- Simple JSON file database (no native compilation needed) ---
const DB_FILE = path.join(__dirname, 'db.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], rooms: [{ id: uuidv4(), name: 'general' }], messages: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDB();

// --- Session (shared between Express and Socket.io) ---
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7,
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

app.post('/api/signup', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Username must be 3+ characters, password 6+ characters' });
  }
  const existing = db.users.find(u => u.username === username);
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  db.users.push({ id, username, password_hash: hash, created_at: new Date().toISOString() });
  saveDB(db);

  req.session.userId = id;
  req.session.username = username;
  res.json({ id, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.users.find(u => u.username === username);
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
});app.get('/api/rooms', requireAuth, (req, res) => {
  const sorted = [...db.rooms].sort((a, b) => a.name.localeCompare(b.name));
  res.json(sorted);
});

app.post('/api/rooms', requireAuth, (req, res) => {
  const { name } = req.body || {};
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Room name too short' });
  const clean = name.trim().slice(0, 40);
  const existing = db.rooms.find(r => r.name === clean);
  if (existing) return res.status(400).json({ error: 'Room already exists' });
  const id = uuidv4();
  db.rooms.push({ id, name: clean });
  saveDB(db);
  res.json({ id, name: clean });
});

app.get('/api/rooms/:roomId/messages', requireAuth, (req, res) => {
  const msgs = db.messages
    .filter(m => m.room_id === req.params.roomId)
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
    .slice(-100);
  res.json(msgs);
});

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

    const message = {
      id,
      room_id: roomId,
      user_id: sess.userId,
      username: sess.username,
      body: trimmed,
      created_at: new Date().toISOString()
    };

    db.messages.push(message);
    saveDB(db);

    io.to(roomId).emit('new_message', message);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Chat server running on port ${PORT}`));
