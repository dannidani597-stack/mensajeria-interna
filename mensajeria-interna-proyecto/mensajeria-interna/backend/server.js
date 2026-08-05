/**
 * Backend simple de mensajeria interna.
 * REST para registro/login/historial + WebSocket para mensajes en tiempo real.
 *
 * Uso interno: JWT sin expiracion corta, sin verificacion de email, etc.
 * Pensado para desplegarse dentro de la red de la empresa (VPN / intranet),
 * no para exponerse directamente a internet publica sin revisarlo primero.
 */
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const http = require('http');
const db = require('./db');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION';
const CHANNEL = 'general'; // MVP: un solo canal. Se puede ampliar a multiples canales despues.

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'mensajeria-interna-backend' });
});

function getChannelId() {
  return db.prepare('SELECT id FROM channels WHERE name = ?').get(CHANNEL).id;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Falta token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalido o expirado' });
  }
}

// ---- Registro ----
app.post('/api/register', (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password || !displayName) {
    return res.status(400).json({ error: 'username, password y displayName son requeridos' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Ese usuario ya existe' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)'
  ).run(username, hash, displayName, Date.now());

  const token = jwt.sign({ id: info.lastInsertRowid, username, displayName }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: info.lastInsertRowid, username, displayName } });
});

// ---- Login ----
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, displayName: user.display_name },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name } });
});

// ---- Historial de mensajes (paginado simple) ----
app.get('/api/messages', authMiddleware, (req, res) => {
  const channelId = getChannelId();
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const before = req.query.before ? parseInt(req.query.before) : Date.now() + 1;

  const rows = db.prepare(`
    SELECT m.id, m.text, m.created_at, u.username, u.display_name
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.channel_id = ? AND m.created_at < ?
    ORDER BY m.created_at DESC
    LIMIT ?
  `).all(channelId, before, limit);

  res.json({ messages: rows.reverse() });
});

// ---- Enviar mensaje (tambien via REST, ademas del WebSocket) ----
app.post('/api/messages', authMiddleware, (req, res) => {
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Mensaje vacio' });

  const channelId = getChannelId();
  const createdAt = Date.now();
  const info = db.prepare(
    'INSERT INTO messages (channel_id, user_id, text, created_at) VALUES (?, ?, ?, ?)'
  ).run(channelId, req.user.id, text.trim(), createdAt);

  const message = {
    id: info.lastInsertRowid,
    text: text.trim(),
    created_at: createdAt,
    username: req.user.username,
    display_name: req.user.displayName,
  };

  broadcast({ type: 'message', message });
  res.json({ message });
});

// ---- Servidor HTTP + WebSocket compartiendo el mismo puerto ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const clients = new Map(); // ws -> { userId, username, displayName }

function broadcast(payload) {
  const data = JSON.stringify(payload);
  for (const ws of clients.keys()) {
    if (ws.readyState === ws.OPEN) ws.send(data);
  }
}

function broadcastPresence() {
  const online = [...clients.values()].map(u => u.displayName);
  broadcast({ type: 'presence', online });
}

wss.on('connection', (ws, req) => {
  // El cliente debe autenticarse con {type:'auth', token:'...'} como primer mensaje.
  let authed = false;

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }

    if (data.type === 'auth') {
      try {
        const user = jwt.verify(data.token, JWT_SECRET);
        clients.set(ws, { userId: user.id, username: user.username, displayName: user.displayName });
        authed = true;
        ws.send(JSON.stringify({ type: 'auth_ok' }));
        broadcastPresence();
      } catch {
        ws.send(JSON.stringify({ type: 'auth_error' }));
        ws.close();
      }
      return;
    }

    if (!authed) return;

    if (data.type === 'message' && data.text && data.text.trim()) {
      const user = clients.get(ws);
      const channelId = getChannelId();
      const createdAt = Date.now();
      const info = db.prepare(
        'INSERT INTO messages (channel_id, user_id, text, created_at) VALUES (?, ?, ?, ?)'
      ).run(channelId, user.userId, data.text.trim(), createdAt);

      broadcast({
        type: 'message',
        message: {
          id: info.lastInsertRowid,
          text: data.text.trim(),
          created_at: createdAt,
          username: user.username,
          display_name: user.displayName,
        },
      });
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    broadcastPresence();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Mensajeria interna backend escuchando en http://localhost:${PORT}`);
  console.log(`WebSocket disponible en ws://localhost:${PORT}/ws`);
});
