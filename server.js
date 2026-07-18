import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');

await fs.ensureDir(dataDir);
if (!(await fs.pathExists(usersFile))) {
  await fs.writeJson(usersFile, {}, { spaces: 2 });
}

async function readUsers() {
  try {
    return await fs.readJson(usersFile);
  } catch (e) {
    return {};
  }
}

async function writeUsers(users) {
  await fs.writeJson(usersFile, users, { spaces: 2 });
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body || {};
  const normEmail = normalizeEmail(email);
  if (!name || !normEmail || !password) {
    return res.status(400).json({ error: 'Name, email and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const users = await readUsers();
  if (users[normEmail]) {
    return res.status(409).json({ error: 'Account already exists.' });
  }
  const hash = await bcrypt.hash(password, 10);
  users[normEmail] = { name, email: normEmail, passwordHash: hash, createdAt: new Date().toISOString() };
  await writeUsers(users);
  const token = signToken({ sub: normEmail, name });
  return res.json({ token, user: { name, email: normEmail } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const normEmail = normalizeEmail(email);
  if (!normEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  const users = await readUsers();
  const user = users[normEmail];
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }
  const token = signToken({ sub: normEmail, name: user.name });
  return res.json({ token, user: { name: user.name, email: normEmail } });
});

app.get('/api/me', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const users = await readUsers();
    const user = users[payload.sub];
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: { name: user.name, email: user.email } });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`PALESTRA backend listening on http://localhost:${PORT}`);
});


