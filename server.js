const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

const USERS_FILE = path.join(__dirname, 'users.json');
const KEYS_FILE = path.join(__dirname, 'keys.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

const adminTokens = new Set();
const sessions = new Map();

function loadSessions() {
  const data = readJson(SESSIONS_FILE, []);
  data.forEach((s) => {
    if (s.token && s.username) sessions.set(s.token, { username: s.username, expiresAt: s.expiresAt });
  });
}
function saveSessions() {
  const arr = Array.from(sessions.entries()).map(([token, s]) => ({ token, username: s.username, expiresAt: s.expiresAt }));
  writeJson(SESSIONS_FILE, arr);
}
loadSessions();

app.use(cors());
app.use(bodyParser.json());

function readJson(filePath, defaultValue) {
  try {
    if (!fs.existsSync(filePath)) return defaultValue;
    const data = fs.readFileSync(filePath, 'utf8');
    return data ? JSON.parse(data) : defaultValue;
  } catch (err) {
    console.error(`Eroare la citirea ${filePath}:`, err);
    return defaultValue;
  }
}

function writeJson(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`Eroare la scrierea ${filePath}:`, err);
  }
}

function getConfig() {
  const env = {
    adminPassword: process.env.ADMIN_PASSWORD,
    adminPath: process.env.ADMIN_PATH,
    discordUrl: process.env.DISCORD_URL,
    youtubeUrl: process.env.YOUTUBE_URL,
  };
  const file = readJson(CONFIG_FILE, {});
  return {
    adminPassword: env.adminPassword || file.adminPassword || 'admin123',
    adminPath: env.adminPath || file.adminPath || '/panel-x9k2m',
    discordUrl: env.discordUrl || file.discordUrl || 'https://discord.gg/',
    youtubeUrl: env.youtubeUrl || file.youtubeUrl || 'https://youtube.com/',
  };
}
function getAdminPassword() {
  return getConfig().adminPassword;
}
function requireUser(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.headers['x-auth-token'];
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ message: 'Unauthorized.' });
  req.session = session;
  req.authToken = token;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !adminTokens.has(token)) {
    return res.status(401).json({ message: 'Neautorizat.' });
  }
  next();
}

function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `${seg()}-${seg()}-${seg()}-${seg()}`;
}

function isKeyValid(keyObj) {
  if (!keyObj) return false;
  if (keyObj.used) return false;
  if (keyObj.status === 'disabled') return false;
  if (new Date(keyObj.expiresAt) < new Date()) return false;
  return true;
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

const HTML_MAP = { 'index.html': 'page-index.html', 'admin.html': 'page-admin.html', 'dashboard.html': 'page-dashboard.html' };
function findHtml(name) {
  const alt = HTML_MAP[name];
  const candidates = [
    path.join(__dirname, 'public', name),
    path.join(__dirname, alt || name),
    path.join(process.cwd(), 'public', name),
    path.join(process.cwd(), alt || name),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

app.get('/', (req, res) => {
  const file = findHtml('index.html');
  if (!file) return res.status(500).send('Missing page. Check page-index.html in repo.');
  res.sendFile(file);
});

const ADMIN_PATH = getConfig().adminPath;
app.get(ADMIN_PATH, (req, res) => {
  const file = findHtml('admin.html');
  if (!file) return res.status(500).send('Missing admin page.');
  res.sendFile(file);
});

app.get('/dashboard', (req, res) => {
  const file = findHtml('dashboard.html');
  if (!file) return res.status(500).send('Fișier lipsă. Verifică că page-dashboard.html e în repo.');
  res.sendFile(file);
});

const staticDirs = [
  path.join(__dirname, 'public'),
  __dirname,
].filter((d) => fs.existsSync(d));
staticDirs.forEach((d) => app.use(express.static(d)));

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const adminPass = getAdminPassword();
  if (password !== adminPass) {
    return res.status(401).json({ message: 'Wrong password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.add(token);
  return res.json({ token });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers['x-admin-token'];
  adminTokens.delete(token);
  return res.json({ message: 'Logged out.' });
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  const keys = readJson(KEYS_FILE, []);
  return res.json(keys);
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
  const { username, durationDays } = req.body;
  if (!username || !durationDays || durationDays < 1) {
    return res.status(400).json({ message: 'Username and duration (days) are required.' });
  }

  const keys = readJson(KEYS_FILE, []);
  let keyStr;
  do {
    keyStr = generateKey();
  } while (keys.some((k) => k.key === keyStr));

  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setDate(expiresAt.getDate() + Number(durationDays));

  const newKey = {
    key: keyStr,
    username: String(username).trim(),
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    status: 'active',
    used: false,
    assignedTo: null,
  };

  keys.push(newKey);
  writeJson(KEYS_FILE, keys);
  return res.json(newKey);
});

app.patch('/api/admin/keys/:key', requireAdmin, (req, res) => {
  const { key } = req.params;
  const { status } = req.body;
  const keys = readJson(KEYS_FILE, []);
  const idx = keys.findIndex((k) => k.key === key);
  if (idx === -1) return res.status(404).json({ message: 'Key not found.' });
  if (status === 'active' || status === 'disabled') {
    keys[idx].status = status;
    writeJson(KEYS_FILE, keys);
  }
  return res.json(keys[idx]);
});

app.delete('/api/admin/keys/:key', requireAdmin, (req, res) => {
  const { key } = req.params;
  const keys = readJson(KEYS_FILE, []);
  const filtered = keys.filter((k) => k.key !== key);
  if (filtered.length === keys.length) return res.status(404).json({ message: 'Key not found.' });
  writeJson(KEYS_FILE, filtered);
  return res.json({ message: 'Key ștearsă.' });
});

function getUserExpiry(username) {
  const keys = readJson(KEYS_FILE, []);
  const userKeys = keys.filter((k) => k.assignedTo === username && k.status !== 'disabled');
  if (userKeys.length === 0) return null;
  const latest = userKeys.reduce((a, k) => (new Date(k.expiresAt) > new Date(a.expiresAt) ? k : a));
  return latest.expiresAt;
}

app.get('/api/config', (req, res) => {
  const cfg = getConfig();
  return res.json({ discordUrl: cfg.discordUrl, youtubeUrl: cfg.youtubeUrl });
});

app.post('/api/login', async (req, res) => {
  const { username, password, key } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const users = readJson(USERS_FILE, []);
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ message: 'Wrong username or password.' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ message: 'Wrong username or password.' });

  if (key) {
    const keys = readJson(KEYS_FILE, []);
    const keyObj = keys.find((k) => k.key === key && k.assignedTo === username);
    if (!keyObj) return res.status(400).json({ message: 'Invalid key for this account.' });
    if (keyObj.status === 'disabled') return res.status(400).json({ message: 'Key disabled.' });
    if (new Date(keyObj.expiresAt) < new Date()) return res.status(400).json({ message: 'Key expired.' });
  }

  const expiresAt = getUserExpiry(username);
  if (!expiresAt || new Date(expiresAt) < new Date()) {
    return res.status(400).json({ message: 'License has expired.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expiresAt });
  saveSessions();

  return res.json({ token, user: { username, expiresAt, theme: user.theme || 'dark' } });
});

app.get('/api/me', requireUser, (req, res) => {
  const { username } = req.session;
  const expiresAt = getUserExpiry(username);
  const users = readJson(USERS_FILE, []);
  const user = users.find((u) => u.username === username);
  if (!expiresAt || new Date(expiresAt) < new Date()) {
    return res.status(403).json({ message: 'Licența a expirat.' });
  }
  return res.json({ username, expiresAt, theme: user?.theme || 'dark' });
});

app.post('/api/extend', requireUser, (req, res) => {
  const { key } = req.body;
  const { username } = req.session;
  if (!key) return res.status(400).json({ message: 'Enter the key.' });

  const keys = readJson(KEYS_FILE, []);
  const keyObj = keys.find((k) => k.key === key);
  if (!keyObj) return res.status(400).json({ message: 'Invalid key.' });
  if (!isKeyValid(keyObj)) return res.status(400).json({ message: 'Invalid or already used key.' });

  const userKeys = keys.filter((k) => k.assignedTo === username);
  const currentLatest = userKeys.length
    ? userKeys.reduce((a, k) => (new Date(k.expiresAt) > new Date(a.expiresAt) ? k : a))
    : null;
  const now = new Date();
  const baseDate = currentLatest && new Date(currentLatest.expiresAt) > now ? new Date(currentLatest.expiresAt) : now;
  const durationMs = new Date(keyObj.expiresAt) - new Date(keyObj.createdAt);
  const newExpiresAt = new Date(baseDate.getTime() + durationMs);

  keyObj.used = true;
  keyObj.assignedTo = username;
  keyObj.expiresAt = newExpiresAt.toISOString();
  writeJson(KEYS_FILE, keys);

  const token = req.authToken;
  if (token) sessions.set(token, { username, expiresAt: keyObj.expiresAt });
  saveSessions();

  return res.json({ message: 'Time added successfully.', expiresAt: keyObj.expiresAt });
});

app.post('/api/change-password', requireUser, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const { username } = req.session;
  if (!oldPassword || !newPassword) return res.status(400).json({ message: 'Fill in all fields.' });

  const users = readJson(USERS_FILE, []);
  const idx = users.findIndex((u) => u.username === username);
  if (idx === -1) return res.status(400).json({ message: 'User not found.' });
  const ok = await bcrypt.compare(oldPassword, users[idx].passwordHash);
  if (!ok) return res.status(400).json({ message: 'Wrong current password.' });
  users[idx].passwordHash = await bcrypt.hash(newPassword, 10);
  writeJson(USERS_FILE, users);
  return res.json({ message: 'Password changed.' });
});

app.patch('/api/settings', requireUser, (req, res) => {
  const { theme } = req.body;
  const { username } = req.session;
  const validThemes = ['dark', 'light', 'red', 'blue', 'green'];
  if (!theme || !validThemes.includes(theme)) return res.status(400).json({ message: 'Invalid theme.' });

  const users = readJson(USERS_FILE, []);
  const idx = users.findIndex((u) => u.username === username);
  if (idx === -1) return res.status(400).json({ message: 'User not found.' });
  users[idx].theme = theme;
  writeJson(USERS_FILE, users);
  return res.json({ message: 'Settings saved.', theme });
});

app.post('/api/logout', requireUser, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.headers['x-auth-token'];
  sessions.delete(token);
  saveSessions();
  return res.json({ message: 'Logged out.' });
});

app.post('/api/register', async (req, res) => {
  const { username, password, key } = req.body;
  if (!username || !password || !key) {
    return res.status(400).json({ message: 'Fill in all fields.' });
  }

  const keys = readJson(KEYS_FILE, []);
  const keyObj = keys.find((k) => k.key === key);

  if (!keyObj) return res.status(400).json({ message: 'Invalid key.' });
  if (!isKeyValid(keyObj)) {
    if (keyObj.used) return res.status(400).json({ message: 'Key already used.' });
    if (keyObj.status === 'disabled') return res.status(400).json({ message: 'Key disabled.' });
    if (new Date(keyObj.expiresAt) < new Date()) return res.status(400).json({ message: 'Key expired.' });
    return res.status(400).json({ message: 'Invalid key.' });
  }

  const users = readJson(USERS_FILE, []);
  if (users.some((u) => u.username === username)) {
    return res.status(400).json({ message: 'Username already exists.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    users.push({ username, passwordHash, key, theme: 'dark' });
    writeJson(USERS_FILE, users);

    keyObj.used = true;
    keyObj.assignedTo = username;
    writeJson(KEYS_FILE, keys);

    const expiresAt = keyObj.expiresAt;
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username, expiresAt });
    saveSessions();

    return res.json({ token, user: { username, expiresAt, theme: 'dark' } });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ message: 'Server error.' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Local: http://localhost:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}${ADMIN_PATH}`);
});
