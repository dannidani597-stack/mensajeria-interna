/**
 * Backend de mensajeria interna — multiples grupos, respuestas, reacciones,
 * no leidos, menciones, roles, mensajes programados/autodestruccion,
 * encuestas, notificaciones push (web), y mas.
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
const webpush = require('web-push');
const db = require('./db');

const PORT = process.env.PORT || 4000;
const RETENTION_DAYS = 40;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;
const MAX_TEXT_LENGTH = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION';
const ADMIN_KEY = process.env.ADMIN_KEY || 'CAMBIA_ESTA_CLAVE_DE_ADMIN';

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ---- Notificaciones push (Web Push con VAPID) ----
// Si no hay llaves configuradas como variables de entorno, se generan al
// vuelo cada vez que arranca el servidor (funciona, pero las suscripciones
// viejas dejan de servir en cada reinicio — para que sean permanentes, hay
// que copiar VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY que se imprimen en el log
// la primera vez, y ponerlas como variables de entorno en Render).
let VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
let VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  const generated = webpush.generateVAPIDKeys();
  VAPID_PUBLIC_KEY = generated.publicKey;
  VAPID_PRIVATE_KEY = generated.privateKey;
  console.warn('\n⚠️  VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY no configuradas — se generaron unas temporales.');
  console.warn('   Para que las notificaciones push sobrevivan un reinicio, copia esto a variables de entorno en Render:');
  console.warn(`   VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY}`);
  console.warn(`   VAPID_PRIVATE_KEY=${VAPID_PRIVATE_KEY}\n`);
}
webpush.setVapidDetails('mailto:admin@example.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

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
  'audio/webm', 'audio/mp4', 'audio/mpeg', 'audio/ogg', 'audio/wav',
]);

// IMPORTANTE (seguridad): la extension del archivo guardado se decide SOLO
// a partir de esta tabla, nunca del nombre original que manda el cliente
// (ver nota larga en versiones anteriores — evita XSS almacenado).
const EXT_BY_MIME = {
  'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif',
  'application/pdf': '.pdf',
  'application/msword': '.doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.ms-excel': '.xls',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/vnd.ms-powerpoint': '.ppt',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
  'text/plain': '.txt', 'text/csv': '.csv',
  'application/zip': '.zip', 'application/x-zip-compressed': '.zip',
  'audio/webm': '.weba', 'audio/mp4': '.m4a', 'audio/mpeg': '.mp3', 'audio/ogg': '.ogg', 'audio/wav': '.wav',
};

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const ext = EXT_BY_MIME[file.mimetype] || '.bin';
      const name = Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext;
      cb(null, name);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
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

// ---- Limitador de intentos (memoria, sin dependencias nuevas) ----
const failedAttempts = new Map();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMIT_MAX = 10;

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
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) failedAttempts.set(key, { count: 1, windowStart: now });
  else entry.count++;
}
function rateLimitCheck(bucket) {
  return (req, res, next) => {
    const ip = getClientIp(req);
    if (isRateLimited(bucket, ip)) return res.status(429).json({ error: 'Demasiados intentos fallidos. Espera unos minutos.' });
    req.rateLimitIp = ip;
    next();
  };
}
function rateLimitVolume(bucket) {
  return (req, res, next) => {
    const ip = getClientIp(req);
    if (isRateLimited(bucket, ip)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
    recordFailedAttempt(bucket, ip);
    next();
  };
}
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

app.get('/', (req, res) => res.json({ ok: true, service: 'mensajeria-interna-backend' }));

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Falta token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(Date.now(), req.user.id);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalido o expirado' });
  }
}

function isMember(channelId, userId) {
  return !!db.prepare('SELECT 1 FROM channel_members WHERE channel_id = ? AND user_id = ?').get(channelId, userId);
}
function memberRole(channelId, userId) {
  const row = db.prepare('SELECT role FROM channel_members WHERE channel_id = ? AND user_id = ?').get(channelId, userId);
  return row ? row.role : null;
}
function isChannelAdmin(channelId, userId) {
  const role = memberRole(channelId, userId);
  return role === 'owner' || role === 'admin';
}

// Extrae menciones @usuario del texto de un mensaje (solo usuarios que
// realmente existan se guardan como mencion).
function extractMentions(text) {
  if (!text) return [];
  const matches = [...text.matchAll(/@([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  if (matches.length === 0) return [];
  const placeholders = matches.map(() => '?').join(',');
  const rows = db.prepare(`SELECT id, username FROM users WHERE username IN (${placeholders})`).all(...matches);
  return rows;
}

// Envia una notificacion push (web) a un usuario si tiene suscripciones
// guardadas. Nunca lanza error hacia arriba — si una suscripcion ya no es
// valida (usuario cerro el navegador hace mucho, etc.), simplemente la borra.
async function sendPushToUser(userId, payload) {
  const subs = db.prepare("SELECT * FROM push_subscriptions WHERE user_id = ? AND platform = 'web'").all(userId);
  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
        JSON.stringify(payload)
      );
    } catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        db.prepare('DELETE FROM push_subscriptions WHERE id = ?').run(sub.id);
      }
    }
  }
}

function isMuted(channelId, userId) {
  return !!db.prepare('SELECT 1 FROM channel_muted WHERE channel_id = ? AND user_id = ?').get(channelId, userId);
}
function isInDndWindow(user) {
  if (!user.dnd_enabled || !user.dnd_start || !user.dnd_end) return false;
  const now = new Date();
  const cur = now.getHours() * 60 + now.getMinutes();
  const [sh, sm] = user.dnd_start.split(':').map(Number);
  const [eh, em] = user.dnd_end.split(':').map(Number);
  const start = sh * 60 + sm, end = eh * 60 + em;
  return start <= end ? (cur >= start && cur < end) : (cur >= start || cur < end);
}

// Notifica (push) a los demas miembros de un canal cuando llega un mensaje,
// SOLO a quien no lo tenga silenciado, no este en "no molestar", y no este
// conectado ahora mismo viendo ese canal (evita doble aviso).
async function notifyChannelMembers(channelId, senderId, senderName, text, activeUserIds) {
  const members = db.prepare('SELECT user_id FROM channel_members WHERE channel_id = ?').all(channelId);
  const channel = db.prepare('SELECT name FROM channels WHERE id = ?').get(channelId);
  for (const m of members) {
    if (m.user_id === senderId) continue;
    if (activeUserIds.has(m.user_id)) continue;
    if (isMuted(channelId, m.user_id)) continue;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(m.user_id);
    if (!user || isInDndWindow(user)) continue;
    await sendPushToUser(m.user_id, {
      title: `${senderName} · ${channel ? channel.name : ''}`,
      body: text || 'Te mandaron un archivo',
      channelId,
    });
  }
}

// ---- Subir una imagen, archivo o nota de voz ----
app.post('/api/upload', authMiddleware, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'No se pudo subir el archivo' });
    if (!req.file) return res.status(400).json({ error: 'Falta el archivo' });
    res.json({
      url: `/uploads/${req.file.filename}`,
      name: req.file.originalname,
      size: req.file.size,
      isImage: req.file.mimetype.startsWith('image/'),
      isAudio: req.file.mimetype.startsWith('audio/'),
    });
  });
});

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
  if (!username || !password || !displayName) return res.status(400).json({ error: 'username, password y displayName son requeridos' });
  if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  if (username.length > 30 || displayName.length > 50) return res.status(400).json({ error: 'Usuario o nombre demasiado largos' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Ese usuario ya existe' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)')
    .run(username, hash, displayName, Date.now());

  const general = db.prepare('SELECT id FROM channels WHERE name = ?').get('general');
  if (general) {
    db.prepare("INSERT OR IGNORE INTO channel_members (channel_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)")
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
  const token = jwt.sign({ id: user.id, username: user.username, displayName: user.display_name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name, avatarUrl: user.avatar_url } });
});

// ---- Directorio de usuarios (para autocompletar invitaciones) ----
app.get('/api/users', authMiddleware, (req, res) => {
  const q = (req.query.q || '').trim();
  let rows;
  if (q) {
    rows = db.prepare('SELECT username, display_name, avatar_url FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY display_name LIMIT 20')
      .all(`%${q}%`, `%${q}%`);
  } else {
    rows = db.prepare('SELECT username, display_name, avatar_url FROM users ORDER BY display_name LIMIT 50').all();
  }
  res.json({ users: rows });
});

// ---- Mi estado "no molestar" ----
app.patch('/api/account/dnd', authMiddleware, (req, res) => {
  const { enabled, start, end } = req.body || {};
  db.prepare('UPDATE users SET dnd_enabled = ?, dnd_start = ?, dnd_end = ? WHERE id = ?')
    .run(enabled ? 1 : 0, start || null, end || null, req.user.id);
  res.json({ ok: true });
});

// ---- Suscripcion a notificaciones push (web) ----
app.post('/api/push/subscribe', authMiddleware, (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) return res.status(400).json({ error: 'Suscripcion invalida' });
  db.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').run(endpoint);
  db.prepare("INSERT INTO push_subscriptions (user_id, platform, endpoint, p256dh, auth, created_at) VALUES (?, 'web', ?, ?, ?, ?)")
    .run(req.user.id, endpoint, keys.p256dh, keys.auth, Date.now());
  res.json({ ok: true, publicKey: VAPID_PUBLIC_KEY });
});
app.get('/api/push/public-key', (req, res) => res.json({ publicKey: VAPID_PUBLIC_KEY }));
// Guarda un token de FCM (Android). El envio real requiere configurar
// Firebase Admin en el servidor (credenciales de un proyecto de Firebase
// propio) — este endpoint deja el token listo para cuando se conecte eso.
app.post('/api/push/subscribe-fcm', authMiddleware, (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Falta el token' });
  db.prepare('DELETE FROM push_subscriptions WHERE fcm_token = ?').run(token);
  db.prepare("INSERT INTO push_subscriptions (user_id, platform, fcm_token, created_at) VALUES (?, 'android', ?, ?)")
    .run(req.user.id, token, Date.now());
  res.json({ ok: true });
});

// ---- Administracion (protegido con ADMIN_KEY, header x-admin-key) ----
app.get('/api/admin/users', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, username, display_name, avatar_url, created_at FROM users ORDER BY username').all();
  res.json({ users });
});

function deleteUserCompletely(userId) {
  const run = db.transaction((id) => {
    db.prepare('DELETE FROM message_reactions WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM message_deleted_for WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM read_state WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM channel_pinned WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM channel_archived WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM channel_muted WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM poll_votes WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM messages WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM channel_members WHERE user_id = ?').run(id);
    db.prepare('UPDATE channels SET created_by = NULL WHERE created_by = ?').run(id);
    db.prepare('DELETE FROM deletion_requests WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  run(userId);
}

app.post('/api/account/request-deletion', authMiddleware, (req, res) => {
  const existing = db.prepare('SELECT id FROM deletion_requests WHERE user_id = ?').get(req.user.id);
  if (existing) return res.json({ ok: true, alreadyRequested: true });
  db.prepare('INSERT INTO deletion_requests (user_id, requested_at) VALUES (?, ?)').run(req.user.id, Date.now());
  res.json({ ok: true });
});

app.post('/api/admin/reset-password', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'username y newPassword (min 4 caracteres) son requeridos' });
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'Ese usuario no existe' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), user.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:username', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.status(404).json({ error: 'Ese usuario no existe' });
  deleteUserCompletely(user.id);
  res.json({ ok: true });
});

app.get('/api/admin/deletion-requests', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const rows = db.prepare(`SELECT dr.id, dr.requested_at, u.username, u.display_name FROM deletion_requests dr JOIN users u ON u.id = dr.user_id ORDER BY dr.requested_at ASC`).all();
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

// Estadisticas simples para el panel de admin.
app.get('/api/admin/stats', rateLimitCheck('admin'), adminAuth, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const totalChannels = db.prepare('SELECT COUNT(*) c FROM channels').get().c;
  const totalMessages = db.prepare('SELECT COUNT(*) c FROM messages').get().c;
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const messagesLast7Days = db.prepare('SELECT COUNT(*) c FROM messages WHERE created_at > ?').get(sevenDaysAgo).c;
  const topUsers = db.prepare(`
    SELECT u.display_name, COUNT(*) as total FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.created_at > ? GROUP BY m.user_id ORDER BY total DESC LIMIT 5
  `).all(sevenDaysAgo);
  res.json({ totalUsers, totalChannels, totalMessages, messagesLast7Days, topUsers });
});

// ---- Canales (grupos) ----
app.get('/api/channels', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.name, c.photo_url, c.description, c.is_announcement_only, c.created_by, c.created_at,
           cm.role,
           (SELECT 1 FROM channel_pinned WHERE channel_id = c.id AND user_id = ?) AS pinned,
           (SELECT 1 FROM channel_archived WHERE channel_id = c.id AND user_id = ?) AS archived,
           (SELECT 1 FROM channel_muted WHERE channel_id = c.id AND user_id = ?) AS muted,
           (SELECT COUNT(*) FROM messages m WHERE m.channel_id = c.id
              AND m.id > COALESCE((SELECT last_read_message_id FROM read_state WHERE channel_id = c.id AND user_id = ?), 0)
              AND m.user_id != ?
              AND (m.scheduled_at IS NULL OR m.scheduled_at <= ?)) AS unread_count
    FROM channels c
    JOIN channel_members cm ON cm.channel_id = c.id
    WHERE cm.user_id = ?
    ORDER BY pinned DESC, c.name = 'general' DESC, c.name ASC
  `).all(req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, Date.now(), req.user.id);
  res.json({ channels: rows });
});

app.post('/api/channels', authMiddleware, (req, res) => {
  const { name } = req.body || {};
  const cleanName = (name || '').trim();
  if (!cleanName) return res.status(400).json({ error: 'El nombre del grupo es requerido' });
  if (cleanName.length > 40) return res.status(400).json({ error: 'El nombre del grupo es demasiado largo' });
  if (cleanName.toLowerCase() === 'general') return res.status(400).json({ error: 'Ese nombre esta reservado' });
  const existing = db.prepare('SELECT id FROM channels WHERE name = ?').get(cleanName);
  if (existing) return res.status(409).json({ error: 'Ya existe un grupo con ese nombre' });

  const createdAt = Date.now();
  const info = db.prepare('INSERT INTO channels (name, created_by, created_at) VALUES (?, ?, ?)').run(cleanName, req.user.id, createdAt);
  db.prepare("INSERT INTO channel_members (channel_id, user_id, role, joined_at) VALUES (?, ?, 'owner', ?)").run(info.lastInsertRowid, req.user.id, createdAt);
  res.json({ channel: { id: info.lastInsertRowid, name: cleanName, created_by: req.user.id, created_at: createdAt } });
});

// Editar foto/descripcion/modo-solo-anuncios de un grupo (solo admin/owner del grupo).
app.patch('/api/channels/:id', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isChannelAdmin(channelId, req.user.id)) return res.status(403).json({ error: 'Solo un admin del grupo puede editarlo' });
  const { description, isAnnouncementOnly } = req.body || {};
  if (description !== undefined) db.prepare('UPDATE channels SET description = ? WHERE id = ?').run((description || '').slice(0, 200), channelId);
  if (isAnnouncementOnly !== undefined) db.prepare('UPDATE channels SET is_announcement_only = ? WHERE id = ?').run(isAnnouncementOnly ? 1 : 0, channelId);
  res.json({ ok: true });
});

app.post('/api/channels/:id/photo', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isChannelAdmin(channelId, req.user.id)) return res.status(403).json({ error: 'Solo un admin del grupo puede cambiar la foto' });
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file || !req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Debe ser una imagen' });
    const url = `/uploads/${req.file.filename}`;
    db.prepare('UPDATE channels SET photo_url = ? WHERE id = ?').run(url, channelId);
    res.json({ url });
  });
});

app.post('/api/channels/:id/invite', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  const { username } = req.body || {};
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const target = db.prepare('SELECT id, display_name FROM users WHERE username = ?').get((username || '').trim());
  if (!target) return res.status(404).json({ error: 'Ese usuario no existe' });
  db.prepare("INSERT OR IGNORE INTO channel_members (channel_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)").run(channelId, target.id, Date.now());
  res.json({ ok: true, displayName: target.display_name });
});

app.get('/api/channels/:id/members', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const members = db.prepare(`
    SELECT u.username, u.display_name, u.avatar_url, u.last_seen_at, cm.role
    FROM channel_members cm JOIN users u ON u.id = cm.user_id
    WHERE cm.channel_id = ? ORDER BY u.display_name
  `).all(channelId);
  res.json({ members });
});

// Cambiar el rol de un miembro (solo owner/admin puede hacerlo).
app.patch('/api/channels/:id/members/:username/role', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isChannelAdmin(channelId, req.user.id)) return res.status(403).json({ error: 'Solo un admin del grupo puede cambiar roles' });
  const { role } = req.body || {};
  if (!['member', 'admin'].includes(role)) return res.status(400).json({ error: 'Rol invalido' });
  const target = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.username);
  if (!target) return res.status(404).json({ error: 'Ese usuario no existe' });
  db.prepare('UPDATE channel_members SET role = ? WHERE channel_id = ? AND user_id = ?').run(role, channelId, target.id);
  res.json({ ok: true });
});

app.post('/api/channels/:id/leave', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  const channel = db.prepare('SELECT name FROM channels WHERE id = ?').get(channelId);
  if (!channel) return res.status(404).json({ error: 'Ese grupo ya no existe' });
  if (channel.name === 'general') return res.status(400).json({ error: 'No puedes salir del canal general' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  db.prepare('DELETE FROM channel_members WHERE channel_id = ? AND user_id = ?').run(channelId, req.user.id);
  res.json({ ok: true });
});

// Fijar / silenciar / archivar un grupo (preferencias por usuario, no afectan a los demas).
for (const action of ['pin', 'mute', 'archive']) {
  const table = { pin: 'channel_pinned', mute: 'channel_muted', archive: 'channel_archived' }[action];
  const col = { pin: 'pinned_at', mute: 'muted_at', archive: 'archived_at' }[action];
  app.post(`/api/channels/:id/${action}`, authMiddleware, (req, res) => {
    const channelId = parseInt(req.params.id);
    if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
    db.prepare(`INSERT OR IGNORE INTO ${table} (channel_id, user_id, ${col}) VALUES (?, ?, ?)`).run(channelId, req.user.id, Date.now());
    res.json({ ok: true });
  });
  app.delete(`/api/channels/:id/${action}`, authMiddleware, (req, res) => {
    const channelId = parseInt(req.params.id);
    db.prepare(`DELETE FROM ${table} WHERE channel_id = ? AND user_id = ?`).run(channelId, req.user.id);
    res.json({ ok: true });
  });
}

// Marca como leido hasta el ultimo mensaje del canal (o hasta uno especifico).
app.post('/api/channels/:id/read', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const lastMsg = db.prepare('SELECT MAX(id) as maxId FROM messages WHERE channel_id = ?').get(channelId);
  const lastId = req.body?.messageId || lastMsg.maxId || 0;
  db.prepare(`
    INSERT INTO read_state (channel_id, user_id, last_read_message_id, updated_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(channel_id, user_id) DO UPDATE SET last_read_message_id = MAX(last_read_message_id, excluded.last_read_message_id), updated_at = excluded.updated_at
  `).run(channelId, req.user.id, lastId, Date.now());
  res.json({ ok: true });
});

// Arma la burbuja de "en respuesta a" para un mensaje, si aplica.
function replyPreview(replyToId) {
  if (!replyToId) return null;
  const row = db.prepare(`
    SELECT m.id, m.text, u.display_name FROM messages m JOIN users u ON u.id = m.user_id WHERE m.id = ?
  `).get(replyToId);
  if (!row) return null;
  return { id: row.id, text: row.text, display_name: row.display_name };
}
function reactionsSummary(messageId) {
  const rows = db.prepare('SELECT emoji, COUNT(*) as count FROM message_reactions WHERE message_id = ? GROUP BY emoji').all(messageId);
  return rows;
}
function hydrateMessage(row, userId) {
  return {
    ...row,
    reply_preview: replyPreview(row.reply_to_id),
    reactions: reactionsSummary(row.id),
  };
}

// ---- Historial de mensajes de un canal ----
app.get('/api/messages', authMiddleware, (req, res) => {
  const channelId = parseInt(req.query.channelId);
  if (!channelId) return res.status(400).json({ error: 'Falta channelId' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const before = req.query.before ? parseInt(req.query.before) : Date.now() + 1;
  const oldestAllowed = Date.now() - RETENTION_MS;

  const rows = db.prepare(`
    SELECT m.*, u.username, u.display_name, u.avatar_url
    FROM messages m JOIN users u ON u.id = m.user_id
    LEFT JOIN message_deleted_for mdf ON mdf.message_id = m.id AND mdf.user_id = ?
    WHERE m.channel_id = ? AND m.created_at < ? AND m.created_at > ?
      AND (m.scheduled_at IS NULL OR m.scheduled_at <= ?)
      AND mdf.message_id IS NULL
    ORDER BY m.created_at DESC
    LIMIT ?
  `).all(req.user.id, channelId, before, oldestAllowed, Date.now(), limit);

  res.json({ messages: rows.reverse().map(r => hydrateMessage(r, req.user.id)) });
});

function insertAndBroadcastMessage({ channelId, userId, username, displayName, text, imageUrl, fileUrl, fileName, fileSize, voiceUrl, voiceDuration, lat, lng, replyToId, scheduledAt, selfDestructMinutes }) {
  const createdAt = Date.now();
  const selfDestructAt = selfDestructMinutes ? createdAt + selfDestructMinutes * 60 * 1000 : null;
  const info = db.prepare(`
    INSERT INTO messages (channel_id, user_id, text, image_url, file_url, file_name, file_size, voice_url, voice_duration, location_lat, location_lng, reply_to_id, scheduled_at, self_destruct_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(channelId, userId, text || null, imageUrl || null, fileUrl || null, fileName || null, fileSize || null, voiceUrl || null, voiceDuration || null, lat || null, lng || null, replyToId || null, scheduledAt || null, selfDestructAt, createdAt);

  const mentions = extractMentions(text);
  for (const u of mentions) db.prepare('INSERT OR IGNORE INTO message_mentions (message_id, mentioned_user_id) VALUES (?, ?)').run(info.lastInsertRowid, u.id);

  const senderRow = db.prepare('SELECT avatar_url FROM users WHERE id = ?').get(userId);
  const message = hydrateMessage({
    id: info.lastInsertRowid, channel_id: channelId, text: text || null, image_url: imageUrl || null,
    file_url: fileUrl || null, file_name: fileName || null, file_size: fileSize || null,
    voice_url: voiceUrl || null, voice_duration: voiceDuration || null,
    location_lat: lat || null, location_lng: lng || null, reply_to_id: replyToId || null,
    scheduled_at: scheduledAt || null, self_destruct_at: selfDestructAt, edited_at: null, pinned: 0,
    created_at: createdAt, username, display_name: displayName, avatar_url: senderRow ? senderRow.avatar_url : null,
  }, userId);

  if (!scheduledAt || scheduledAt <= Date.now()) {
    broadcastToChannel(channelId, { type: 'message', message });
  }
  return message;
}

app.post('/api/messages', authMiddleware, (req, res) => {
  const { channelId, text, imageUrl, fileUrl, fileName, fileSize, replyToId, scheduledAt } = req.body || {};
  if (!channelId) return res.status(400).json({ error: 'Falta channelId' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const channel = db.prepare('SELECT is_announcement_only FROM channels WHERE id = ?').get(channelId);
  if (channel && channel.is_announcement_only && !isChannelAdmin(channelId, req.user.id)) {
    return res.status(403).json({ error: 'Solo un admin puede publicar en este canal de anuncios' });
  }
  const cleanText = (text || '').trim().slice(0, MAX_TEXT_LENGTH);
  if (!cleanText && !imageUrl && !fileUrl) return res.status(400).json({ error: 'Mensaje vacio' });

  const message = insertAndBroadcastMessage({
    channelId, userId: req.user.id, username: req.user.username, displayName: req.user.displayName,
    text: cleanText, imageUrl, fileUrl, fileName, fileSize, replyToId, scheduledAt,
  });
  res.json({ message });
});

// ---- Editar mi propio mensaje (guarda el texto anterior en el historial) ----
app.patch('/api/messages/:id', authMiddleware, (req, res) => {
  const { text } = req.body || {};
  const cleanText = (text || '').trim().slice(0, MAX_TEXT_LENGTH);
  if (!cleanText) return res.status(400).json({ error: 'El mensaje no puede quedar vacio' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Ese mensaje ya no existe' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Solo puedes editar tus propios mensajes' });

  db.prepare('INSERT INTO message_edit_history (message_id, old_text, edited_at) VALUES (?, ?, ?)').run(msg.id, msg.text, Date.now());
  const editedAt = Date.now();
  db.prepare('UPDATE messages SET text = ?, edited_at = ? WHERE id = ?').run(cleanText, editedAt, msg.id);
  broadcastToChannel(msg.channel_id, { type: 'message_edited', channelId: msg.channel_id, id: msg.id, text: cleanText, edited_at: editedAt });
  res.json({ ok: true });
});

app.get('/api/messages/:id/history', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT channel_id FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || !isMember(msg.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  const history = db.prepare('SELECT old_text, edited_at FROM message_edit_history WHERE message_id = ? ORDER BY edited_at ASC').all(req.params.id);
  res.json({ history });
});

// ---- Borrar: para todos (autor) o solo para mi (cualquier miembro) ----
app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Ese mensaje ya no existe' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Solo puedes borrar tus propios mensajes' });
  db.prepare('DELETE FROM messages WHERE id = ?').run(msg.id);
  for (const url of [msg.image_url, msg.file_url, msg.voice_url]) {
    if (!url) continue;
    fs.unlink(path.join(UPLOADS_DIR, path.basename(url)), () => {});
  }
  broadcastToChannel(msg.channel_id, { type: 'message_deleted', channelId: msg.channel_id, id: msg.id });
  res.json({ ok: true });
});
app.post('/api/messages/:id/delete-for-me', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT channel_id FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || !isMember(msg.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  db.prepare('INSERT OR IGNORE INTO message_deleted_for (message_id, user_id) VALUES (?, ?)').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ---- Reacciones ----
const ALLOWED_EMOJI = new Set(['👍', '❤️', '😂', '😮', '😢', '🙏']);
app.post('/api/messages/:id/react', authMiddleware, (req, res) => {
  const { emoji } = req.body || {};
  if (!ALLOWED_EMOJI.has(emoji)) return res.status(400).json({ error: 'Emoji no permitido' });
  const msg = db.prepare('SELECT channel_id FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || !isMember(msg.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  db.prepare('INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)').run(req.params.id, req.user.id, emoji, Date.now());
  const reactions = reactionsSummary(req.params.id);
  broadcastToChannel(msg.channel_id, { type: 'reactions_updated', channelId: msg.channel_id, id: parseInt(req.params.id), reactions });
  res.json({ ok: true, reactions });
});
app.delete('/api/messages/:id/react/:emoji', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT channel_id FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || !isMember(msg.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  db.prepare('DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?').run(req.params.id, req.user.id, req.params.emoji);
  const reactions = reactionsSummary(req.params.id);
  broadcastToChannel(msg.channel_id, { type: 'reactions_updated', channelId: msg.channel_id, id: parseInt(req.params.id), reactions });
  res.json({ ok: true, reactions });
});

// ---- Fijar / desfijar un mensaje dentro del grupo ----
app.post('/api/messages/:id/pin', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT channel_id FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || !isChannelAdmin(msg.channel_id, req.user.id)) return res.status(403).json({ error: 'Solo un admin del grupo puede fijar mensajes' });
  db.prepare('UPDATE messages SET pinned = 1 WHERE id = ?').run(req.params.id);
  broadcastToChannel(msg.channel_id, { type: 'message_pinned', channelId: msg.channel_id, id: parseInt(req.params.id), pinned: true });
  res.json({ ok: true });
});
app.delete('/api/messages/:id/pin', authMiddleware, (req, res) => {
  const msg = db.prepare('SELECT channel_id FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || !isChannelAdmin(msg.channel_id, req.user.id)) return res.status(403).json({ error: 'Solo un admin del grupo puede desfijar mensajes' });
  db.prepare('UPDATE messages SET pinned = 0 WHERE id = ?').run(req.params.id);
  broadcastToChannel(msg.channel_id, { type: 'message_pinned', channelId: msg.channel_id, id: parseInt(req.params.id), pinned: false });
  res.json({ ok: true });
});
app.get('/api/channels/:id/pinned-messages', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const rows = db.prepare(`SELECT m.*, u.display_name FROM messages m JOIN users u ON u.id = m.user_id WHERE m.channel_id = ? AND m.pinned = 1 ORDER BY m.created_at DESC`).all(channelId);
  res.json({ messages: rows });
});

// ---- Reenviar un mensaje a otro grupo ----
app.post('/api/messages/:id/forward', authMiddleware, (req, res) => {
  const { channelId } = req.body || {};
  const original = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!original || !isMember(original.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces al grupo destino' });

  const message = insertAndBroadcastMessage({
    channelId, userId: req.user.id, username: req.user.username, displayName: req.user.displayName,
    text: original.text, imageUrl: original.image_url, fileUrl: original.file_url, fileName: original.file_name, fileSize: original.file_size,
  });
  res.json({ message });
});

// ---- Buscar mensajes en todos mis grupos ----
app.get('/api/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.status(400).json({ error: 'Escribe al menos 2 caracteres' });
  const rows = db.prepare(`
    SELECT m.id, m.channel_id, m.text, m.created_at, u.display_name, c.name as channel_name
    FROM messages m
    JOIN users u ON u.id = m.user_id
    JOIN channels c ON c.id = m.channel_id
    JOIN channel_members cm ON cm.channel_id = c.id AND cm.user_id = ?
    WHERE m.text LIKE ? ORDER BY m.created_at DESC LIMIT 50
  `).all(req.user.id, `%${q}%`);
  res.json({ results: rows });
});

// ---- Exportar un grupo como texto plano (el cliente lo convierte a PDF/TXT) ----
app.get('/api/channels/:id/export', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const channel = db.prepare('SELECT name FROM channels WHERE id = ?').get(channelId);
  const rows = db.prepare(`
    SELECT m.text, m.created_at, u.display_name FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.channel_id = ? ORDER BY m.created_at ASC
  `).all(channelId);
  const lines = rows.map(r => `[${new Date(r.created_at).toLocaleString('es-MX')}] ${r.display_name}: ${r.text || '(archivo/imagen)'}`);
  res.json({ channelName: channel.name, text: lines.join('\n') });
});

// ---- Encuestas ----
app.post('/api/channels/:id/polls', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!isMember(channelId, req.user.id)) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const { question, options } = req.body || {};
  if (!question || !Array.isArray(options) || options.length < 2) return res.status(400).json({ error: 'Se necesita una pregunta y al menos 2 opciones' });

  const createdAt = Date.now();
  const pollInfo = db.prepare('INSERT INTO polls (channel_id, question, created_by, created_at) VALUES (?, ?, ?, ?)').run(channelId, question.slice(0, 200), req.user.id, createdAt);
  const optionIds = options.slice(0, 10).map(text => {
    const info = db.prepare('INSERT INTO poll_options (poll_id, text) VALUES (?, ?)').run(pollInfo.lastInsertRowid, String(text).slice(0, 100));
    return { id: info.lastInsertRowid, text };
  });

  const message = insertAndBroadcastMessage({
    channelId, userId: req.user.id, username: req.user.username, displayName: req.user.displayName,
    text: `📊 Encuesta: ${question}`,
  });
  db.prepare('UPDATE polls SET message_id = ? WHERE id = ?').run(message.id, pollInfo.lastInsertRowid);
  broadcastToChannel(channelId, { type: 'poll_created', channelId, poll: { id: pollInfo.lastInsertRowid, question, options: optionIds, messageId: message.id } });
  res.json({ poll: { id: pollInfo.lastInsertRowid, question, options: optionIds } });
});

app.get('/api/polls/:id', authMiddleware, (req, res) => {
  const poll = db.prepare('SELECT * FROM polls WHERE id = ?').get(req.params.id);
  if (!poll || !isMember(poll.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  const options = db.prepare('SELECT * FROM poll_options WHERE poll_id = ?').all(poll.id);
  const votes = db.prepare('SELECT option_id, COUNT(*) as count FROM poll_votes WHERE poll_id = ? GROUP BY option_id').all(poll.id);
  const myVote = db.prepare('SELECT option_id FROM poll_votes WHERE poll_id = ? AND user_id = ?').get(poll.id, req.user.id);
  res.json({ poll, options, votes, myVote: myVote ? myVote.option_id : null });
});

app.post('/api/polls/:id/vote', authMiddleware, (req, res) => {
  const { optionId } = req.body || {};
  const poll = db.prepare('SELECT * FROM polls WHERE id = ?').get(req.params.id);
  if (!poll || !isMember(poll.channel_id, req.user.id)) return res.status(403).json({ error: 'No autorizado' });
  db.prepare('INSERT INTO poll_votes (poll_id, option_id, user_id, voted_at) VALUES (?, ?, ?, ?) ON CONFLICT(poll_id, user_id) DO UPDATE SET option_id = excluded.option_id, voted_at = excluded.voted_at')
    .run(poll.id, optionId, req.user.id, Date.now());
  const votes = db.prepare('SELECT option_id, COUNT(*) as count FROM poll_votes WHERE poll_id = ? GROUP BY option_id').all(poll.id);
  broadcastToChannel(poll.channel_id, { type: 'poll_voted', channelId: poll.channel_id, pollId: poll.id, votes });
  res.json({ ok: true, votes });
});

// ---- Estados / historias (24 horas, visibles a todo el equipo) ----
app.post('/api/stories', authMiddleware, (req, res) => {
  const { text, imageUrl } = req.body || {};
  if (!text && !imageUrl) return res.status(400).json({ error: 'El estado no puede estar vacio' });
  const createdAt = Date.now();
  db.prepare('INSERT INTO messages (channel_id, user_id, text, image_url, self_destruct_at, created_at) VALUES (0, ?, ?, ?, ?, ?)')
    .run(req.user.id, (text || '').slice(0, 300), imageUrl || null, createdAt + 24 * 60 * 60 * 1000, createdAt);
  res.json({ ok: true });
});
app.get('/api/stories', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT m.id, m.text, m.image_url, m.created_at, m.self_destruct_at, u.display_name, u.avatar_url
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.channel_id = 0 AND m.self_destruct_at > ? ORDER BY m.created_at DESC
  `).all(Date.now());
  res.json({ stories: rows });
});

// ---- Servidor HTTP + WebSocket compartiendo el mismo puerto ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2 * 1024 * 1024 });

// ws -> { userId, username, displayName, channelId (canal activo), avatarUrl }
const clients = new Map();
let typingTimers = new Map(); // "channelId:userId" -> timeout

function broadcastToChannel(channelId, payload) {
  const data = JSON.stringify(payload);
  for (const [ws, info] of clients.entries()) {
    if (info.channelId === channelId && ws.readyState === ws.OPEN) ws.send(data);
  }
}
function broadcastPresence(channelId) {
  const names = [...clients.values()].filter(u => u.channelId === channelId).map(u => u.displayName);
  broadcastToChannel(channelId, { type: 'presence', channelId, online: names });
}
function activeUserIdsInChannel(channelId) {
  return new Set([...clients.values()].filter(u => u.channelId === channelId).map(u => u.userId));
}
function sendToUser(userId, payload) {
  const data = JSON.stringify(payload);
  for (const [ws, info] of clients.entries()) {
    if (info.userId === userId && ws.readyState === ws.OPEN) ws.send(data);
  }
}

wss.on('connection', (ws) => {
  let authed = false;

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }

    if (data.type === 'auth') {
      try {
        const user = jwt.verify(data.token, JWT_SECRET);
        const dbUser = db.prepare('SELECT avatar_url FROM users WHERE id = ?').get(user.id);
        clients.set(ws, { userId: user.id, username: user.username, displayName: user.displayName, channelId: null, avatarUrl: dbUser ? dbUser.avatar_url : null });
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

    // ---- Indicador "escribiendo..." (ephemeral, no se guarda en base de datos) ----
    if (data.type === 'typing' && info.channelId) {
      const channelId = info.channelId;
      const key = `${channelId}:${info.userId}`;
      broadcastToChannel(channelId, { type: 'typing', channelId, userId: info.userId, displayName: info.displayName });
      clearTimeout(typingTimers.get(key));
      typingTimers.set(key, setTimeout(() => {
        broadcastToChannel(channelId, { type: 'typing_stopped', channelId, userId: info.userId });
        typingTimers.delete(key);
      }, 3000));
      return;
    }

    // ---- Señalizacion de llamadas de voz/video (WebRTC) — solo se retransmite,
    // el servidor no procesa audio/video, solo pasa los mensajes entre los dos. ----
    if (data.type === 'call_offer' || data.type === 'call_answer' || data.type === 'call_ice' || data.type === 'call_end') {
      if (data.toUserId) sendToUser(data.toUserId, { ...data, fromUserId: info.userId, fromDisplayName: info.displayName });
      return;
    }

    if (data.type === 'message' && info.channelId && ((data.text && data.text.trim()) || data.imageUrl || data.fileUrl || data.voiceUrl || (data.lat && data.lng))) {
      const channelId = info.channelId;
      const channel = db.prepare('SELECT is_announcement_only FROM channels WHERE id = ?').get(channelId);
      if (channel && channel.is_announcement_only && !isChannelAdmin(channelId, info.userId)) return;

      const cleanText = (data.text || '').trim().slice(0, MAX_TEXT_LENGTH);
      const message = insertAndBroadcastMessage({
        channelId, userId: info.userId, username: info.username, displayName: info.displayName,
        text: cleanText, imageUrl: data.imageUrl, fileUrl: data.fileUrl, fileName: data.fileName, fileSize: data.fileSize,
        voiceUrl: data.voiceUrl, voiceDuration: data.voiceDuration, lat: data.lat, lng: data.lng,
        replyToId: data.replyToId, selfDestructMinutes: data.selfDestructMinutes,
      });

      notifyChannelMembers(channelId, info.userId, info.displayName, cleanText, activeUserIdsInChannel(channelId)).catch(() => {});
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
  if (JWT_SECRET === 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION') {
    console.warn('\n⚠️  ADVERTENCIA DE SEGURIDAD: JWT_SECRET no esta configurado.\n');
  }
  if (ADMIN_KEY === 'CAMBIA_ESTA_CLAVE_DE_ADMIN') {
    console.warn('\n⚠️  ADVERTENCIA DE SEGURIDAD: ADMIN_KEY no esta configurado.\n');
  }
});

// ---- Trabajos periodicos ----

// Libera mensajes programados cuya hora ya llego.
function releaseScheduledMessages() {
  const due = db.prepare('SELECT * FROM messages WHERE scheduled_at IS NOT NULL AND scheduled_at <= ?').all(Date.now());
  for (const m of due) {
    const user = db.prepare('SELECT username, display_name, avatar_url FROM users WHERE id = ?').get(m.user_id);
    if (!user) continue;
    broadcastToChannel(m.channel_id, { type: 'message', message: hydrateMessage({ ...m, username: user.username, display_name: user.display_name, avatar_url: user.avatar_url }, m.user_id) });
    db.prepare('UPDATE messages SET scheduled_at = NULL WHERE id = ?').run(m.id);
  }
}
setInterval(releaseScheduledMessages, 30 * 1000);

// Borra mensajes que ya cumplieron su autodestruccion (incluye "estados/historias" de 24h).
function cleanupSelfDestruct() {
  const due = db.prepare('SELECT id, channel_id, image_url, file_url, voice_url FROM messages WHERE self_destruct_at IS NOT NULL AND self_destruct_at <= ?').all(Date.now());
  for (const m of due) {
    db.prepare('DELETE FROM messages WHERE id = ?').run(m.id);
    for (const url of [m.image_url, m.file_url, m.voice_url]) {
      if (url) fs.unlink(path.join(UPLOADS_DIR, path.basename(url)), () => {});
    }
    if (m.channel_id !== 0) broadcastToChannel(m.channel_id, { type: 'message_deleted', channelId: m.channel_id, id: m.id });
  }
}
setInterval(cleanupSelfDestruct, 60 * 1000);

// Borra mensajes (y sus archivos) con mas de 40 dias de antiguedad.
function cleanupOldMessages() {
  const cutoff = Date.now() - RETENTION_MS;
  try {
    const oldOnes = db.prepare('SELECT image_url, file_url, voice_url FROM messages WHERE created_at < ? AND channel_id != 0').all(cutoff);
    const info = db.prepare('DELETE FROM messages WHERE created_at < ? AND channel_id != 0').run(cutoff);
    if (info.changes > 0) {
      console.log(`Limpieza automatica: ${info.changes} mensaje(s) de mas de ${RETENTION_DAYS} dias eliminados.`);
      for (const m of oldOnes) {
        for (const url of [m.image_url, m.file_url, m.voice_url]) {
          if (url) fs.unlink(path.join(UPLOADS_DIR, path.basename(url)), () => {});
        }
      }
    }
  } catch (err) {
    console.error('Error en la limpieza automatica de mensajes:', err.message);
  }
}
cleanupOldMessages();
setInterval(cleanupOldMessages, 24 * 60 * 60 * 1000);
