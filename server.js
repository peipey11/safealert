const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database('sos.db');

// ─── DB SETUP ────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    emergency_status INTEGER DEFAULT 0,
    latitude REAL,
    longitude REAL,
    last_updated DATETIME
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS sos_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    user_name TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    action TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'sos-demo-secret-key-2024',
  name: 'safealert.sid',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

const requireAuth = (req, res, next) => {
  // userId can be 0 for admin, so check explicitly for undefined/null
  if (req.session.userId === undefined || req.session.userId === null) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
};

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const result = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(name, email, hashed);

  res.json({ success: true, message: 'Registered successfully' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Admin check
  if (email === 'admin@demo.com' && password === 'admin123') {
    req.session.isAdmin = true;
    req.session.userId = 0;
    return res.json({ success: true, role: 'admin' });
  }

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.isAdmin = false;

  res.json({ success: true, role: 'user', name: user.name });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/me', (req, res) => {
  // Allow unauthenticated check - return 401 gracefully
  if (req.session.userId === undefined || req.session.userId === null) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (req.session.isAdmin) return res.json({ isAdmin: true });
  const user = db.prepare('SELECT id, name, email, emergency_status, latitude, longitude FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  res.json(user);
});

// ─── USER ROUTES ─────────────────────────────────────────────────────────────

app.get('/contacts', requireAuth, (req, res) => {
  const contacts = db.prepare('SELECT * FROM contacts WHERE user_id = ?').all(req.session.userId);
  res.json(contacts);
});

app.post('/add-contact', requireAuth, (req, res) => {
  const { name, phone } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });

  const count = db.prepare('SELECT COUNT(*) as cnt FROM contacts WHERE user_id = ?').get(req.session.userId);
  if (count.cnt >= 3) return res.status(400).json({ error: 'Maximum 3 contacts allowed' });

  db.prepare('INSERT INTO contacts (user_id, name, phone) VALUES (?, ?, ?)').run(req.session.userId, name, phone);
  res.json({ success: true });
});

app.delete('/delete-contact/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM contacts WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  res.json({ success: true });
});

app.post('/activate-sos', requireAuth, (req, res) => {
  const { latitude, longitude } = req.body;
  if (latitude === undefined || latitude === null || longitude === undefined || longitude === null) {
    return res.status(400).json({ error: 'Location required' });
  }

  db.prepare(`
    UPDATE users SET emergency_status = 1, latitude = ?, longitude = ?, last_updated = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(latitude, longitude, req.session.userId);

  const user = db.prepare('SELECT name FROM users WHERE id = ?').get(req.session.userId);
  db.prepare(`
    INSERT INTO sos_log (user_id, user_name, latitude, longitude, action)
    VALUES (?, ?, ?, ?, 'ACTIVATED')
  `).run(req.session.userId, user.name, latitude, longitude);

  res.json({ success: true });
});

app.post('/deactivate-sos', requireAuth, (req, res) => {
  const user = db.prepare('SELECT name, latitude, longitude FROM users WHERE id = ?').get(req.session.userId);
  db.prepare('UPDATE users SET emergency_status = 0 WHERE id = ?').run(req.session.userId);

  db.prepare(`
    INSERT INTO sos_log (user_id, user_name, latitude, longitude, action)
    VALUES (?, ?, ?, ?, 'CANCELLED')
  `).run(req.session.userId, user.name, user.latitude, user.longitude);

  res.json({ success: true });
});

app.post('/update-location', requireAuth, (req, res) => {
  const { latitude, longitude } = req.body;
  if (latitude === undefined || longitude === undefined) return res.json({ success: false });
  db.prepare(`
    UPDATE users SET latitude = ?, longitude = ?, last_updated = CURRENT_TIMESTAMP
    WHERE id = ? AND emergency_status = 1
  `).run(latitude, longitude, req.session.userId);
  res.json({ success: true });
});

// ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

app.get('/admin/emergencies', requireAdmin, (req, res) => {
  const active = db.prepare(`
    SELECT id, name, latitude, longitude, last_updated
    FROM users WHERE emergency_status = 1
  `).all();
  res.json(active);
});

app.get('/admin/log', requireAdmin, (req, res) => {
  const logs = db.prepare(`
    SELECT * FROM sos_log ORDER BY timestamp DESC LIMIT 100
  `).all();
  res.json(logs);
});

app.get('/admin/stats', requireAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const activeEmergencies = db.prepare('SELECT COUNT(*) as count FROM users WHERE emergency_status = 1').get().count;
  const totalActivations = db.prepare("SELECT COUNT(*) as count FROM sos_log WHERE action = 'ACTIVATED'").get().count;
  res.json({ totalUsers, activeEmergencies, totalActivations });
});

// ─── START ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚨 Emergency SOS Server running at http://localhost:${PORT}`);
  console.log(`   Admin login: admin@demo.com / admin123\n`);
});
