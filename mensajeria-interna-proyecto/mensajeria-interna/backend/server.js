/**
 * Backend de mensajeria interna con soporte de multiples grupos (canales).
 * REST para registro/login/historial/canales + WebSocket para mensajes en tiempo real.
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
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('./db');

const PORT = process.env.PORT || 4000;
const RETENTION_DAYS = 40;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;
const MAX_TEXT_LENGTH = 5000; // limite razonable para un mensaje de chat
const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION';
const ADMIN_KEY = process.env.ADMIN_KEY || 'CAMBIA_ESTA_CLAVE_DE_ADMIN';

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const ALLOWED_MIME = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain', 'text/csv',
  'application/zip', 'application/x-zip-compressed',
]);

// IMPORTANTE (seguridad): la extension del archivo guardado se decide SOLO
// a partir de esta tabla, nunca del nombre original que manda el cliente.
// Si se usara la extension original, alguien podria declarar mimetype
// "image/jpeg" pero nombrar su archivo "ataque.html" con contenido
// ejecutable adentro; al servirse desde /uploads con extension .html, el
// navegador lo interpretaria como pagina real (XSS almacenado). Mapeando
// la extension desde el mimetype ya validado, ese archivo se guarda como
// .jpg y el navegador nunca lo ejecuta como HTML/JS.
const EXT_BY_MIME = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'application/pdf': '.pdf',
  'application/msword': '.doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.ms-excel': '.xls',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/vnd.ms-powerpoint': '.ppt',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
  'text/plain': '.txt',
  'text/csv': '.csv',
  'application/zip': '.zip',
  'application/x-zip-compressed': '.zip',
};

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      // fileFilter ya corrio antes de esto, asi que file.mimetype esta
      // garantizado a ser uno de los permitidos en ALLOWED_MIME.
      const ext = EXT_BY_MIME[file.mimetype] || '.bin';
      const name = Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext;
      cb(null, name);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB por archivo
  fileFilter: (req, file, cb) => {
    const ok = ALLOWED_MIME.has(file.mimetype);
    cb(ok ? null : new Error('Tipo de archivo no permitido'), ok);
  },
});

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname + '/public'));
app.use('/uploads', express.static(UPLOADS_DIR));

// ---- Limitador de intentos simple (memoria, sin dependencias nuevas) ----
// Protege login/admin contra intentos automatizados de adivinar contraseñas
// o la clave de administrador. Solo cuenta los intentos FALLIDOS (no los
// exitosos) — asi, si varias personas de la oficina inician sesion bien
// desde la misma IP compartida, nadie se queda bloqueado por error.
// Por proceso: se reinicia si el servidor se reinicia, aceptable para el
// volumen de un equipo interno (no se necesita Redis para esto).
const failedAttempts = new Map(); // key: "bucket:ip" -> { count, windowStart }
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutos
const RATE_LIMIT_MAX = 10; // intentos fallidos por ventana

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
}

function isRateLimited(bucket, ip) {
  const entry = failedAttempts.get(`${bucket}:${ip}`);
  if (!entry) return false;
  if (Date.now() - entry.windowStart > RATE_LIMIT_WINDOW_MS) return false;
  return entry.count >= RATE_LIMIT_MAX;
}

function recordFailedAttempt(bucket, ip) {
  const key = `${bucket}:${ip}`;
  const entry = failedAttempts.get(key);
  const now = Date.now();
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    failedAttempts.set(key, { count: 1, windowStart: now });
  } else {
    entry.count++;
  }
}

// Bloquea la solicitud ANTES de procesarla si ya se supero el limite de
// fallos recientes. Las rutas deben llamar a recordFailedAttempt() ellas
// mismas cuando el intento efectivamente falle (contraseña o clave incorrecta).
function rateLimitCheck(bucket) {
  return (req, res, next) => {
    const ip = getClientIp(req);
    if (isRateLimited(bucket, ip)) {
      return res.status(429).json({ error: 'Demasiados intentos fallidos. Espera unos minutos y vuelve a intentar.' });
    }
    req.rateLimitBucket = bucket;
    req.rateLimitIp = ip;
    next();
  };
}

// Limita intentos de registro por volumen total (no solo fallidos), ya que
// aqui el riesgo es spam de cuentas falsas, no adivinar un secreto existente.
function rateLimitVolume(bucket) {
  return (req, res, next) => {
    const ip = getClientIp(req);
    if (isRateLimited(bucket, ip)) {
      return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos y vuelve a intentar.' });
    }
    recordFailedAttempt(bucket, ip);
    next();
  };
}

// Limpieza periodica del mapa de intentos para no acumular memoria indefinidamente.
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of failedAttempts.entries()) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) failedAttempts.delete(key);
  }
}, RATE_LIMIT_WINDOW_MS);

function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) {
    if (req.rateLimitIp) recordFailedAttempt('admin', req.rateLimitIp);
    return res.status(401).json({ error: 'Clave de administrador incorrecta' });
  }
  next();
}

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'mensajeria-interna-backend' });
});

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

function isMember(channelId, userId) {
  return !!db.prepare('SELECT 1 FROM channel_members WHERE channel_id = ? AND user_id = ?').get(channelId, userId);
}

// ---- Subir una imagen o archivo (devuelve la info para incluir en un mensaje) ----
app.post('/api/upload', authMiddleware, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'No se pudo subir el archivo' });
    if (!req.file) return res.status(400).json({ error: 'Falta el archivo' });
    res.json({
      url: `/uploads/${req.file.filename}`,
      name: req.file.originalname,
      size: req.file.size,
      isImage: req.file.mimetype.startsWith('image/'),
    });
  });
});

// ---- Subir/cambiar mi foto de perfil ----
app.post('/api/account/avatar', authMiddleware, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'No se pudo subir la imagen' });
    if (!req.file) return res.status(400).json({ error: 'Falta la imagen' });
    if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Debe ser una imagen' });

    const url = `/uploads/${req.file.filename}`;
    db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').run(url, req.user.id);
    res.json({ url });
  });
});

// ---- Registro ----
app.post('/api/register', rateLimitVolume('register'), (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password || !displayName) {
    return res.status(400).json({ error: 'username, password y displayName son requeridos' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  }
  if (username.length > 30 || displayName.length > 50) {
    return res.status(400).json({ error: 'Usuario o nombre demasiado largos' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Ese usuario ya existe' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)'
  ).run(username, hash, displayName, Date.now());

  // Todo usuario nuevo entra automaticamente al canal "general" (abierto a todo el equipo).
  const general = db.prepare('SELECT id FROM channels WHERE name = ?').get('general');
  if (general) {
    db.prepare('INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)')
      .run(general.id, info.lastInsertRowid, Date.now());
  }

  const token = jwt.sign({ id: info.lastInsertRowid, username, displayName }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: info.lastInsertRowid, username, displayName, avatarUrl: null } });
});

// ---- Login ----
app.post('/api/login', rateLimitCheck('login'), (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    recordFailedAttempt('login', req.rateLimitIp);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, displayName: user.display_name },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name, avatarUrl: user.avatar_url } });
});

// ---- Administracion (protegido con ADMIN_KEY, header x-admin-key) ----
app.get('/api/admin/users', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, username, display_name, avatar_url, created_at FROM users ORDER BY username').all();
  res.json({ users });
});

function deleteUserCompletely(userId) {
  const run = db.transaction((id) => {
    db.prepare('DELETE FROM messages WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM channel_members WHERE user_id = ?').run(id);
    db.prepare('UPDATE channels SET created_by = NULL WHERE created_by = ?').run(id);
    db.prepare('DELETE FROM deletion_requests WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  run(userId);
}

// ---- Solicitud de eliminacion de cuenta (la pide el propio usuario) ----
app.post('/api/account/request-deletion', authMiddleware, (req, res) => {
  const existing = db.prepare('SELECT id FROM deletion_requests WHERE user_id = ?').get(req.user.id);
  if (existing) return res.json({ ok: true, alreadyRequested: true });

  db.prepare('INSERT INTO deletion_requests (user_id, requested_at) VALUES (?, ?)').run(req.user.id, Date.now());
  res.json({ ok: true });
});

app.post('/api/admin/reset-password', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'username y newPassword (min 4 caracteres) son requeridos' });
  }
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'Ese usuario no existe' });

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

// Elimina un usuario por completo directamente (uso manual del admin, sin solicitud previa).
app.delete('/api/admin/users/:username', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.status(404).json({ error: 'Ese usuario no existe' });
  deleteUserCompletely(user.id);
  res.json({ ok: true });
});

// ---- Solicitudes de eliminacion pendientes (revision del admin) ----
app.get('/api/admin/deletion-requests', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT dr.id, dr.requested_at, u.username, u.display_name
    FROM deletion_requests dr JOIN users u ON u.id = dr.user_id
    ORDER BY dr.requested_at ASC
  `).all();
  res.json({ requests: rows });
});

app.post('/api/admin/deletion-requests/:id/approve', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const request = db.prepare('SELECT user_id FROM deletion_requests WHERE id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Esa solicitud ya no existe' });
  deleteUserCompletely(request.user_id);
  res.json({ ok: true });
});

app.post('/api/admin/deletion-requests/:id/reject', rateLimitCheck('admin'), adminAuth, (req, res) => {
  db.prepare('DELETE FROM deletion_requests WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---- Canales (grupos) ----

// Lista los canales de los que el usuario es miembro.
app.get('/api/channels', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.name, c.created_by, c.created_at
    FROM channels c
    JOIN channel_members cm ON cm.channel_id = c.id
    WHERE cm.user_id = ?
    ORDER BY c.name = 'general' DESC, c.name ASC
  `).all(req.user.id);
  res.json({ channels: rows });
});

// Crea un canal nuevo (privado: solo el creador es miembro al inicio).
app.post('/api/channels', authMiddleware, (req, res) => {
  const { name } = req.body || {};
  const cleanName = (name || '').trim();
  if (!cleanName) return res.status(400).json({ error: 'El nombre del grupo es requerido' });
  if (cleanName.length > 40) return res.status(400).json({ error: 'El nombre del grupo es demasiado largo' });
  if (cleanName.toLowerCase() === 'general') return res.status(400).json({ error: 'Ese nombre esta reservado' });

  const existing = db.prepare('SELECT id FROM channels WHERE name = ?').get(cleanName);
  if (existing) return res.status(409).json({ error: 'Ya existe un grupo con ese nombre' });

  const createdAt = Date.now();
  const info = db.prepare('INSERT INTO channels (name, created_by, created_at) VALUES (?, ?, ?)')
    .run(cleanName, req.user.id, createdAt);
  db.prepare('INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)')
    .run(info.lastInsertRowid, req.user.id, createdAt);

  res.json({ channel: { id: info.lastInsertRowid, name: cleanName, created_by: req.user.id, created_at: createdAt } });
});

// Invita a un usuario existente a un canal (solo miembros del canal pueden invitar).
app.post('/api/channels/:id/invite', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  const { username } = req.body || {};
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  const target = db.prepare('SELECT id, display_name FROM users WHERE username = ?').get((username || '').trim());
  if (!target) return res.status(404).json({ error: 'Ese usuario no existe' });

  db.prepare('INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)')
    .run(channelId, target.id, Date.now());

  res.json({ ok: true, displayName: target.display_name });
});

// Lista los miembros de un canal (solo miembros pueden verla).
app.get('/api/channels/:id/members', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  const members = db.prepare(`
    SELECT u.username, u.display_name
    FROM channel_members cm JOIN users u ON u.id = cm.user_id
    WHERE cm.channel_id = ?
    ORDER BY u.display_name
  `).all(channelId);
  res.json({ members });
});

// Salir de un grupo (no aplica a "general", que es abierto para todo el
// equipo — salirse de ahi no tendria forma de volver a entrar por cuenta
// propia, ya que solo se une automaticamente al registrarte).
app.post('/api/channels/:id/leave', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  const channel = db.prepare('SELECT name FROM channels WHERE id = ?').get(channelId);
  if (!channel) return res.status(404).json({ error: 'Ese grupo ya no existe' });
  if (channel.name === 'general') return res.status(400).json({ error: 'No puedes salir del canal general' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  db.prepare('DELETE FROM channel_members WHERE channel_id = ? AND user_id = ?').run(channelId, req.user.id);
  res.json({ ok: true });
});

// ---- Historial de mensajes de un canal (paginado simple) ----
app.get('/api/messages', authMiddleware, (req, res) => {
  const channelId = parseInt(req.query.channelId);
  if (!channelId) return res.status(400).json({ error: 'Falta channelId' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const before = req.query.before ? parseInt(req.query.before) : Date.now() + 1;
  const oldestAllowed = Date.now() - RETENTION_MS;

  const rows = db.prepare(`
    SELECT m.id, m.text, m.image_url, m.file_url, m.file_name, m.file_size, m.edited_at, m.created_at, u.username, u.display_name, u.avatar_url
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.channel_id = ? AND m.created_at < ? AND m.created_at > ?
    ORDER BY m.created_at DESC
    LIMIT ?
  `).all(channelId, before, oldestAllowed, limit);

  res.json({ messages: rows.reverse() });
});

// ---- Enviar mensaje (tambien via REST, ademas del WebSocket) ----
app.post('/api/messages', authMiddleware, (req, res) => {
  const { channelId, text, imageUrl, fileUrl, fileName, fileSize } = req.body || {};
  if (!channelId) return res.status(400).json({ error: 'Falta channelId' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  const cleanText = (text || '').trim().slice(0, MAX_TEXT_LENGTH);
  if (!cleanText && !imageUrl && !fileUrl) return res.status(400).json({ error: 'Mensaje vacio' });

  const createdAt = Date.now();
  const info = db.prepare(
    'INSERT INTO messages (channel_id, user_id, text, image_url, file_url, file_name, file_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(channelId, req.user.id, cleanText || null, imageUrl || null, fileUrl || null, fileName || null, fileSize || null, createdAt);

  const senderRow = db.prepare('SELECT avatar_url FROM users WHERE id = ?').get(req.user.id);

  const message = {
    id: info.lastInsertRowid,
    channel_id: channelId,
    text: cleanText || null,
    image_url: imageUrl || null,
    file_url: fileUrl || null,
    file_name: fileName || null,
    file_size: fileSize || null,
    created_at: createdAt,
    username: req.user.username,
    display_name: req.user.displayName,
    avatar_url: senderRow ? senderRow.avatar_url : null,
  };

  broadcastToChannel(channelId, { type: 'message', message });
  res.json({ message });
});

// ---- Editar mi propio mensaje ----
app.patch('/api/messages/:id', authMiddleware, (req, res) => {
  const { text } = req.body || {};
  const cleanText = (text || '').trim().slice(0, MAX_TEXT_LENGTH);
  if (!cleanText) return res.status(400).json({ error: 'El mensaje no puede quedar vacio' });

  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Ese mensaje ya no existe' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Solo puedes editar tus propios mensajes' });

  const editedAt = Date.now();
  db.prepare('UPDATE messages SET text = ?, edited_at = ? WHERE id = ?').run(cleanText, editedAt, msg.id);

  broadcastToChannel(msg.channel_id, {
    type: 'message_edited',
    channelId: msg.channel_id,
    id: msg.id,
    text: cleanText,
    edited_at: editedAt,
  });
  res.json({ ok: true });
});

// ---- Borrar mi propio mensaje ----
app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Ese mensaje ya no existe' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Solo puedes borrar tus propios mensajes' });

  db.prepare('DELETE FROM messages WHERE id = ?').run(msg.id);

  // Limpia tambien el archivo adjunto en disco (si tenia), para no dejarlo
  // huerfano para siempre: la limpieza automatica de 40 dias solo revisa
  // mensajes que siguen en la base de datos, y este ya se borro de ahi.
  for (const url of [msg.image_url, msg.file_url]) {
    if (!url) continue;
    const filePath = path.join(UPLOADS_DIR, path.basename(url));
    fs.unlink(filePath, () => {});
  }

  broadcastToChannel(msg.channel_id, {
    type: 'message_deleted',
    channelId: msg.channel_id,
    id: msg.id,
  });
  res.json({ ok: true });
});

// ---- Servidor HTTP + WebSocket compartiendo el mismo puerto ----
const server = http.createServer(app);
// maxPayload evita que alguien mande un mensaje gigante por WebSocket para
// llenar el disco (limitado en Render) — sin esto, el limite por defecto
// de la libreria "ws" es 100 MB por mensaje, demasiado generoso.
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 1 * 1024 * 1024 });

// ws -> { userId, username, displayName, channelId (canal activo en este momento) }
const clients = new Map();

function broadcastToChannel(channelId, payload) {
  const data = JSON.stringify(payload);
  for (const [ws, info] of clients.entries()) {
    if (info.channelId === channelId && ws.readyState === ws.OPEN) ws.send(data);
  }
}

function broadcastPresence(channelId) {
  const names = [...clients.values()]
    .filter(u => u.channelId === channelId)
    .map(u => u.displayName);
  broadcastToChannel(channelId, { type: 'presence', channelId, online: names });
}

wss.on('connection', (ws) => {
  let authed = false;

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }

    if (data.type === 'auth') {
      try {
        const user = jwt.verify(data.token, JWT_SECRET);
        clients.set(ws, { userId: user.id, username: user.username, displayName: user.displayName, channelId: null });
        authed = true;
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      } catch {
        ws.send(JSON.stringify({ type: 'auth_error' }));
        ws.close();
      }
      return;
    }

    if (!authed) return;
    const info = clients.get(ws);

    if (data.type === 'join') {
      const channelId = parseInt(data.channelId);
      if (!isMember(channelId, info.userId)) {
        ws.send(JSON.stringify({ type: 'join_error', error: 'No perteneces a ese grupo' }));
        return;
      }
      const prevChannel = info.channelId;
      info.channelId = channelId;
      if (prevChannel && prevChannel !== channelId) broadcastPresence(prevChannel);
      broadcastPresence(channelId);
      return;
    }

    if (data.type === 'message' && info.channelId && ((data.text && data.text.trim()) || data.imageUrl || data.fileUrl)) {
      const channelId = info.channelId;
      const createdAt = Date.now();
      const cleanText = (data.text || '').trim().slice(0, MAX_TEXT_LENGTH);
      const insertInfo = db.prepare(
        'INSERT INTO messages (channel_id, user_id, text, image_url, file_url, file_name, file_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(channelId, info.userId, cleanText || null, data.imageUrl || null, data.fileUrl || null, data.fileName || null, data.fileSize || null, createdAt);

      const senderRow = db.prepare('SELECT avatar_url FROM users WHERE id = ?').get(info.userId);

      broadcastToChannel(channelId, {
        type: 'message',
        message: {
          id: insertInfo.lastInsertRowid,
          channel_id: channelId,
          text: cleanText || null,
          image_url: data.imageUrl || null,
          file_url: data.fileUrl || null,
          file_name: data.fileName || null,
          file_size: data.fileSize || null,
          created_at: createdAt,
          username: info.username,
          display_name: info.displayName,
          avatar_url: senderRow ? senderRow.avatar_url : null,
        },
      });
    }
  });

  ws.on('close', () => {
    const info = clients.get(ws);
    clients.delete(ws);
    if (info && info.channelId) broadcastPresence(info.channelId);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Mensajeria interna backend escuchando en http://localhost:${PORT}`);
  console.log(`WebSocket disponible en ws://localhost:${PORT}/ws`);

  // Aviso de seguridad: estos valores por defecto viven en el codigo fuente
  // (visibles para cualquiera con acceso al repo). Si el servidor arranca
  // sin haber configurado JWT_SECRET/ADMIN_KEY como variables de entorno,
  // cualquiera que lea el codigo podria forjar tokens de sesion o entrar
  // al panel de administrador.
  if (JWT_SECRET === 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION') {
    console.warn('\n⚠️  ADVERTENCIA DE SEGURIDAD: JWT_SECRET no esta configurado (usando el valor por defecto del codigo). Configuralo como variable de entorno antes de usar esto en produccion.\n');
  }
  if (ADMIN_KEY === 'CAMBIA_ESTA_CLAVE_DE_ADMIN') {
    console.warn('\n⚠️  ADVERTENCIA DE SEGURIDAD: ADMIN_KEY no esta configurado (usando el valor por defecto del codigo). Cualquiera podria entrar al panel de administrador. Configuralo como variable de entorno.\n');
  }
});

// ---- Limpieza automatica: borra mensajes (y sus archivos adjuntos) con
// mas de 40 dias de antiguedad. Corre al iniciar el servidor y luego una
// vez al dia mientras el proceso siga vivo. ----
function cleanupOldMessages() {
  const cutoff = Date.now() - RETENTION_MS;
  try {
    const oldOnes = db.prepare('SELECT image_url, file_url FROM messages WHERE created_at < ?').all(cutoff);
    const info = db.prepare('DELETE FROM messages WHERE created_at < ?').run(cutoff);

    if (info.changes > 0) {
      console.log(`Limpieza automatica: ${info.changes} mensaje(s) de mas de ${RETENTION_DAYS} dias eliminados.`);
      for (const m of oldOnes) {
        for (const url of [m.image_url, m.file_url]) {
          if (!url) continue;
          const filePath = path.join(UPLOADS_DIR, path.basename(url));
          fs.unlink(filePath, () => {}); // best-effort, no pasa nada si ya no existe
        }
      }
    }
  } catch (err) {
    console.error('Error en la limpieza automatica de mensajes:', err.message);
  }
}

cleanupOldMessages();
setInterval(cleanupOldMessages, 24 * 60 * 60 * 1000);
