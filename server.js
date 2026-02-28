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

const adminTokens = new Set();

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

function getAdminPassword() {
  if (process.env.ADMIN_PASSWORD) return process.env.ADMIN_PASSWORD;
  const config = readJson(CONFIG_FILE, {});
  return config.adminPassword || 'admin123';
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

app.get('/', (req, res) => {
  const file = path.join(__dirname, 'public', 'index.html');
  if (!fs.existsSync(file)) {
    console.error('index.html not found at', file);
    return res.status(500).send('Configurare incorectă.');
  }
  res.sendFile(file);
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const adminPass = getAdminPassword();
  if (password !== adminPass) {
    return res.status(401).json({ message: 'Parolă greșită.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.add(token);
  return res.json({ token });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers['x-admin-token'];
  adminTokens.delete(token);
  return res.json({ message: 'Deconectat.' });
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  const keys = readJson(KEYS_FILE, []);
  return res.json(keys);
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
  const { username, durationDays } = req.body;
  if (!username || !durationDays || durationDays < 1) {
    return res.status(400).json({ message: 'Username și durata (zile) sunt obligatorii.' });
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
  if (idx === -1) return res.status(404).json({ message: 'Key negăsită.' });
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
  if (filtered.length === keys.length) return res.status(404).json({ message: 'Key negăsită.' });
  writeJson(KEYS_FILE, filtered);
  return res.json({ message: 'Key ștearsă.' });
});

app.post('/api/register', async (req, res) => {
  const { username, password, key } = req.body;
  if (!username || !password || !key) {
    return res.status(400).json({ message: 'Completează toate câmpurile.' });
  }

  const keys = readJson(KEYS_FILE, []);
  const keyObj = keys.find((k) => k.key === key);

  if (!keyObj) return res.status(400).json({ message: 'Key invalidă.' });
  if (!isKeyValid(keyObj)) {
    if (keyObj.used) return res.status(400).json({ message: 'Key deja folosită.' });
    if (keyObj.status === 'disabled') return res.status(400).json({ message: 'Key dezactivată.' });
    if (new Date(keyObj.expiresAt) < new Date()) return res.status(400).json({ message: 'Key expirată.' });
    return res.status(400).json({ message: 'Key invalidă.' });
  }

  const users = readJson(USERS_FILE, []);
  if (users.some((u) => u.username === username)) {
    return res.status(400).json({ message: 'Username-ul există deja.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    users.push({ username, passwordHash, key });
    writeJson(USERS_FILE, users);

    keyObj.used = true;
    keyObj.assignedTo = username;
    writeJson(KEYS_FILE, keys);

    return res.json({ message: 'Cont creat cu succes.' });
  } catch (err) {
    console.error('Eroare la înregistrare:', err);
    return res.status(500).json({ message: 'Eroare de server.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password, key } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username și parola sunt obligatorii.' });
  }

  const users = readJson(USERS_FILE, []);
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ message: 'Username sau parolă greșite.' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ message: 'Username sau parolă greșite.' });

  if (key) {
    const keys = readJson(KEYS_FILE, []);
    const keyObj = keys.find((k) => k.key === key && k.assignedTo === username);
    if (!keyObj) return res.status(400).json({ message: 'Key invalidă pentru acest cont.' });
    if (keyObj.status === 'disabled') return res.status(400).json({ message: 'Key dezactivată.' });
    if (new Date(keyObj.expiresAt) < new Date()) return res.status(400).json({ message: 'Key expirată.' });
  }

  return res.json({ message: 'Logat cu succes.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server pornit pe portul ${PORT}`);
  console.log(`Acces local: http://localhost:${PORT}`);
  console.log(`Acces din rețea: http://<IP-TAU>:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}/admin`);
});
