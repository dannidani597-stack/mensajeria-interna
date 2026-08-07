/**
 * Backend de mensajeria interna — multiples grupos, respuestas, reacciones,
 * no leidos, menciones, roles, mensajes programados/autodestruccion,
 * encuestas, notificaciones push (web), y mas. Base de datos: Postgres (Neon).
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
const { pool, initDb } = require('./db');

// Ejecuta una consulta y regresa las filas (rows). Atajo para no escribir
// "(await pool.query(...)).rows" en cada linea.
async function q(sql, params = []) {
  const res = await pool.query(sql, params);
  return res.rows;
}
async function qOne(sql, params = []) {
  const rows = await q(sql, params);
  return rows[0] || null;
}

const PORT = process.env.PORT || 4000;
const RETENTION_DAYS = 40;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;
const MAX_TEXT_LENGTH = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION';
const ADMIN_KEY = process.env.ADMIN_KEY || 'CAMBIA_ESTA_CLAVE_DE_ADMIN';

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ---- Notificaciones push (Web Push con VAPID) ----
let VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
let VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  const generated = webpush.generateVAPIDKeys();
  VAPID_PUBLIC_KEY = generated.publicKey;
  VAPID_PRIVATE_KEY = generated.privateKey;
  console.warn('\n⚠️  VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY no configuradas — se generaron unas temporales.');
  console.warn('   Copia esto a variables de entorno en Render para que sobrevivan un reinicio:');
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
// a partir de esta tabla, nunca del nombre original del cliente (evita XSS almacenado).
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

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Falta token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    await pool.query('UPDATE users SET last_seen_at = $1 WHERE id = $2', [Date.now(), req.user.id]);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalido o expirado' });
  }
}

async function isMember(channelId, userId) {
  return !!(await qOne('SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2', [channelId, userId]));
}
async function memberRole(channelId, userId) {
  const row = await qOne('SELECT role FROM channel_members WHERE channel_id = $1 AND user_id = $2', [channelId, userId]);
  return row ? row.role : null;
}
async function isChannelAdmin(channelId, userId) {
  const role = await memberRole(channelId, userId);
  return role === 'owner' || role === 'admin';
}

async function extractMentions(text) {
  if (!text) return [];
  const matches = [...text.matchAll(/@([a-zA-Z0-9_]+)/g)].map(m => m[1]);
  if (matches.length === 0) return [];
  const placeholders = matches.map((_, i) => `$${i + 1}`).join(',');
  return q(`SELECT id, username FROM users WHERE username IN (${placeholders})`, matches);
}

async function sendPushToUser(userId, payload) {
  const subs = await q("SELECT * FROM push_subscriptions WHERE user_id = $1 AND platform = 'web'", [userId]);
  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
        JSON.stringify(payload)
      );
    } catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        await pool.query('DELETE FROM push_subscriptions WHERE id = $1', [sub.id]);
      }
    }
  }
}
async function isMuted(channelId, userId) {
  return !!(await qOne('SELECT 1 FROM channel_muted WHERE channel_id = $1 AND user_id = $2', [channelId, userId]));
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
async function notifyChannelMembers(channelId, senderId, senderName, text, activeUserIds) {
  const members = await q('SELECT user_id FROM channel_members WHERE channel_id = $1', [channelId]);
  const channel = await qOne('SELECT name FROM channels WHERE id = $1', [channelId]);
  for (const m of members) {
    if (m.user_id === senderId) continue;
    if (activeUserIds.has(m.user_id)) continue;
    if (await isMuted(channelId, m.user_id)) continue;
    const user = await qOne('SELECT * FROM users WHERE id = $1', [m.user_id]);
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
  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message || 'No se pudo subir la imagen' });
    if (!req.file) return res.status(400).json({ error: 'Falta la imagen' });
    if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Debe ser una imagen' });
    const url = `/uploads/${req.file.filename}`;
    await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [url, req.user.id]);
    res.json({ url });
  });
});

// ---- Registro ----
app.post('/api/register', rateLimitVolume('register'), async (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password || !displayName) return res.status(400).json({ error: 'username, password y displayName son requeridos' });
  if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  if (username.length > 30 || displayName.length > 50) return res.status(400).json({ error: 'Usuario o nombre demasiado largos' });

  const existing = await qOne('SELECT id FROM users WHERE username = $1', [username]);
  if (existing) return res.status(409).json({ error: 'Ese usuario ya existe' });

  const hash = bcrypt.hashSync(password, 10);
  const info = await qOne(
    'INSERT INTO users (username, password_hash, display_name, created_at) VALUES ($1, $2, $3, $4) RETURNING id',
    [username, hash, displayName, Date.now()]
  );
  const userId = info.id;

  const general = await qOne('SELECT id FROM channels WHERE name = $1', ['general']);
  if (general) {
    await pool.query(
      "INSERT INTO channel_members (channel_id, user_id, role, joined_at) VALUES ($1, $2, 'member', $3) ON CONFLICT DO NOTHING",
      [general.id, userId, Date.now()]
    );
  }

  const token = jwt.sign({ id: userId, username, displayName }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: userId, username, displayName, avatarUrl: null } });
});

// ---- Login ----
app.post('/api/login', rateLimitCheck('login'), async (req, res) => {
  const { username, password } = req.body || {};
  const user = await qOne('SELECT * FROM users WHERE username = $1', [username]);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    recordFailedAttempt('login', req.rateLimitIp);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, displayName: user.display_name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name, avatarUrl: user.avatar_url } });
});

// ---- Directorio de usuarios ----
app.get('/api/users', authMiddleware, async (req, res) => {
  const query = (req.query.q || '').trim();
  let rows;
  if (query) {
    rows = await q('SELECT username, display_name, avatar_url FROM users WHERE username ILIKE $1 OR display_name ILIKE $1 ORDER BY display_name LIMIT 20', [`%${query}%`]);
  } else {
    rows = await q('SELECT username, display_name, avatar_url FROM users ORDER BY display_name LIMIT 50');
  }
  res.json({ users: rows });
});

// ---- Mi estado "no molestar" ----
app.patch('/api/account/dnd', authMiddleware, async (req, res) => {
  const { enabled, start, end } = req.body || {};
  await pool.query('UPDATE users SET dnd_enabled = $1, dnd_start = $2, dnd_end = $3 WHERE id = $4',
    [enabled ? 1 : 0, start || null, end || null, req.user.id]);
  res.json({ ok: true });
});

// ---- Suscripcion a notificaciones push ----
app.post('/api/push/subscribe', authMiddleware, async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) return res.status(400).json({ error: 'Suscripcion invalida' });
  await pool.query('DELETE FROM push_subscriptions WHERE endpoint = $1', [endpoint]);
  await pool.query("INSERT INTO push_subscriptions (user_id, platform, endpoint, p256dh, auth, created_at) VALUES ($1, 'web', $2, $3, $4, $5)",
    [req.user.id, endpoint, keys.p256dh, keys.auth, Date.now()]);
  res.json({ ok: true, publicKey: VAPID_PUBLIC_KEY });
});
app.get('/api/push/public-key', (req, res) => res.json({ publicKey: VAPID_PUBLIC_KEY }));
app.post('/api/push/subscribe-fcm', authMiddleware, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Falta el token' });
  await pool.query('DELETE FROM push_subscriptions WHERE fcm_token = $1', [token]);
  await pool.query("INSERT INTO push_subscriptions (user_id, platform, fcm_token, created_at) VALUES ($1, 'android', $2, $3)",
    [req.user.id, token, Date.now()]);
  res.json({ ok: true });
});

// ---- Administracion ----
app.get('/api/admin/users', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  const users = await q('SELECT id, username, display_name, avatar_url, created_at FROM users ORDER BY username');
  res.json({ users });
});

async function deleteUserCompletely(userId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM message_reactions WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM message_deleted_for WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM read_state WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM push_subscriptions WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM channel_pinned WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM channel_archived WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM channel_muted WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM poll_votes WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM messages WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM channel_members WHERE user_id = $1', [userId]);
    await client.query('UPDATE channels SET created_by = NULL WHERE created_by = $1', [userId]);
    await client.query('DELETE FROM deletion_requests WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM users WHERE id = $1', [userId]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

app.post('/api/account/request-deletion', authMiddleware, async (req, res) => {
  const existing = await qOne('SELECT id FROM deletion_requests WHERE user_id = $1', [req.user.id]);
  if (existing) return res.json({ ok: true, alreadyRequested: true });
  await pool.query('INSERT INTO deletion_requests (user_id, requested_at) VALUES ($1, $2)', [req.user.id, Date.now()]);
  res.json({ ok: true });
});

app.post('/api/admin/reset-password', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'username y newPassword (min 4 caracteres) son requeridos' });
  const user = await qOne('SELECT id FROM users WHERE username = $1', [username]);
  if (!user) return res.status(404).json({ error: 'Ese usuario no existe' });
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [bcrypt.hashSync(newPassword, 10), user.id]);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:username', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  const user = await qOne('SELECT id FROM users WHERE username = $1', [req.params.username]);
  if (!user) return res.status(404).json({ error: 'Ese usuario no existe' });
  await deleteUserCompletely(user.id);
  res.json({ ok: true });
});

app.get('/api/admin/deletion-requests', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  const rows = await q(`SELECT dr.id, dr.requested_at, u.username, u.display_name FROM deletion_requests dr JOIN users u ON u.id = dr.user_id ORDER BY dr.requested_at ASC`);
  res.json({ requests: rows });
});
app.post('/api/admin/deletion-requests/:id/approve', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  const request = await qOne('SELECT user_id FROM deletion_requests WHERE id = $1', [req.params.id]);
  if (!request) return res.status(404).json({ error: 'Esa solicitud ya no existe' });
  await deleteUserCompletely(request.user_id);
  res.json({ ok: true });
});
app.post('/api/admin/deletion-requests/:id/reject', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  await pool.query('DELETE FROM deletion_requests WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/admin/stats', rateLimitCheck('admin'), adminAuth, async (req, res) => {
  const totalUsers = (await qOne('SELECT COUNT(*) c FROM users')).c;
  const totalChannels = (await qOne('SELECT COUNT(*) c FROM channels')).c;
  const totalMessages = (await qOne('SELECT COUNT(*) c FROM messages')).c;
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const messagesLast7Days = (await qOne('SELECT COUNT(*) c FROM messages WHERE created_at > $1', [sevenDaysAgo])).c;
  const topUsers = await q(`
    SELECT u.display_name, COUNT(*) as total FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.created_at > $1 GROUP BY m.user_id, u.display_name ORDER BY total DESC LIMIT 5
  `, [sevenDaysAgo]);
  res.json({ totalUsers, totalChannels, totalMessages, messagesLast7Days, topUsers });
});

// ---- Canales (grupos) ----
app.get('/api/channels', authMiddleware, async (req, res) => {
  const rows = await q(`
    SELECT c.id, c.name, c.photo_url, c.description, c.is_announcement_only, c.created_by, c.created_at,
           cm.role,
           (SELECT 1 FROM channel_pinned WHERE channel_id = c.id AND user_id = $1) AS pinned,
           (SELECT 1 FROM channel_archived WHERE channel_id = c.id AND user_id = $1) AS archived,
           (SELECT 1 FROM channel_muted WHERE channel_id = c.id AND user_id = $1) AS muted,
           (SELECT COUNT(*) FROM messages m WHERE m.channel_id = c.id
              AND m.id > COALESCE((SELECT last_read_message_id FROM read_state WHERE channel_id = c.id AND user_id = $1), 0)
              AND m.user_id != $1
              AND (m.scheduled_at IS NULL OR m.scheduled_at <= $2)) AS unread_count
    FROM channels c
    JOIN channel_members cm ON cm.channel_id = c.id
    WHERE cm.user_id = $1
    ORDER BY pinned DESC NULLS LAST, (c.name = 'general') DESC, c.name ASC
  `, [req.user.id, Date.now()]);
  res.json({ channels: rows });
});

app.post('/api/channels', authMiddleware, async (req, res) => {
  const { name } = req.body || {};
  const cleanName = (name || '').trim();
  if (!cleanName) return res.status(400).json({ error: 'El nombre del grupo es requerido' });
  if (cleanName.length > 40) return res.status(400).json({ error: 'El nombre del grupo es demasiado largo' });
  if (cleanName.toLowerCase() === 'general') return res.status(400).json({ error: 'Ese nombre esta reservado' });
  const existing = await qOne('SELECT id FROM channels WHERE name = $1', [cleanName]);
  if (existing) return res.status(409).json({ error: 'Ya existe un grupo con ese nombre' });

  const createdAt = Date.now();
  const info = await qOne('INSERT INTO channels (name, created_by, created_at) VALUES ($1, $2, $3) RETURNING id', [cleanName, req.user.id, createdAt]);
  await pool.query("INSERT INTO channel_members (channel_id, user_id, role, joined_at) VALUES ($1, $2, 'owner', $3)", [info.id, req.user.id, createdAt]);
  res.json({ channel: { id: info.id, name: cleanName, created_by: req.user.id, created_at: createdAt } });
});

app.patch('/api/channels/:id', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isChannelAdmin(channelId, req.user.id))) return res.status(403).json({ error: 'Solo un admin del grupo puede editarlo' });
  const { description, isAnnouncementOnly } = req.body || {};
  if (description !== undefined) await pool.query('UPDATE channels SET description = $1 WHERE id = $2', [(description || '').slice(0, 200), channelId]);
  if (isAnnouncementOnly !== undefined) await pool.query('UPDATE channels SET is_announcement_only = $1 WHERE id = $2', [isAnnouncementOnly ? 1 : 0, channelId]);
  res.json({ ok: true });
});

app.post('/api/channels/:id/photo', authMiddleware, (req, res) => {
  const channelId = parseInt(req.params.id);
  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!(await isChannelAdmin(channelId, req.user.id))) return res.status(403).json({ error: 'Solo un admin del grupo puede cambiar la foto' });
    if (!req.file || !req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Debe ser una imagen' });
    const url = `/uploads/${req.file.filename}`;
    await pool.query('UPDATE channels SET photo_url = $1 WHERE id = $2', [url, channelId]);
    res.json({ url });
  });
});

app.post('/api/channels/:id/invite', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  const { username } = req.body || {};
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const target = await qOne('SELECT id, display_name FROM users WHERE username = $1', [(username || '').trim()]);
  if (!target) return res.status(404).json({ error: 'Ese usuario no existe' });
  await pool.query("INSERT INTO channel_members (channel_id, user_id, role, joined_at) VALUES ($1, $2, 'member', $3) ON CONFLICT DO NOTHING", [channelId, target.id, Date.now()]);
  res.json({ ok: true, displayName: target.display_name });
});

app.get('/api/channels/:id/members', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const members = await q(`
    SELECT u.username, u.display_name, u.avatar_url, u.last_seen_at, cm.role
    FROM channel_members cm JOIN users u ON u.id = cm.user_id
    WHERE cm.channel_id = $1 ORDER BY u.display_name
  `, [channelId]);
  res.json({ members });
});

app.patch('/api/channels/:id/members/:username/role', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isChannelAdmin(channelId, req.user.id))) return res.status(403).json({ error: 'Solo un admin del grupo puede cambiar roles' });
  const { role } = req.body || {};
  if (!['member', 'admin'].includes(role)) return res.status(400).json({ error: 'Rol invalido' });
  const target = await qOne('SELECT id FROM users WHERE username = $1', [req.params.username]);
  if (!target) return res.status(404).json({ error: 'Ese usuario no existe' });
  await pool.query('UPDATE channel_members SET role = $1 WHERE channel_id = $2 AND user_id = $3', [role, channelId, target.id]);
  res.json({ ok: true });
});

app.post('/api/channels/:id/leave', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  const channel = await qOne('SELECT name FROM channels WHERE id = $1', [channelId]);
  if (!channel) return res.status(404).json({ error: 'Ese grupo ya no existe' });
  if (channel.name === 'general') return res.status(400).json({ error: 'No puedes salir del canal general' });
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  await pool.query('DELETE FROM channel_members WHERE channel_id = $1 AND user_id = $2', [channelId, req.user.id]);
  res.json({ ok: true });
});

for (const action of ['pin', 'mute', 'archive']) {
  const table = { pin: 'channel_pinned', mute: 'channel_muted', archive: 'channel_archived' }[action];
  const col = { pin: 'pinned_at', mute: 'muted_at', archive: 'archived_at' }[action];
  app.post(`/api/channels/:id/${action}`, authMiddleware, async (req, res) => {
    const channelId = parseInt(req.params.id);
    if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
    await pool.query(`INSERT INTO ${table} (channel_id, user_id, ${col}) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [channelId, req.user.id, Date.now()]);
    res.json({ ok: true });
  });
  app.delete(`/api/channels/:id/${action}`, authMiddleware, async (req, res) => {
    const channelId = parseInt(req.params.id);
    await pool.query(`DELETE FROM ${table} WHERE channel_id = $1 AND user_id = $2`, [channelId, req.user.id]);
    res.json({ ok: true });
  });
}

app.post('/api/channels/:id/read', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const lastMsg = await qOne('SELECT MAX(id) as "maxId" FROM messages WHERE channel_id = $1', [channelId]);
  const lastId = req.body?.messageId || lastMsg.maxId || 0;
  await pool.query(`
    INSERT INTO read_state (channel_id, user_id, last_read_message_id, updated_at) VALUES ($1, $2, $3, $4)
    ON CONFLICT (channel_id, user_id) DO UPDATE SET last_read_message_id = GREATEST(read_state.last_read_message_id, excluded.last_read_message_id), updated_at = excluded.updated_at
  `, [channelId, req.user.id, lastId, Date.now()]);
  res.json({ ok: true });
});

async function replyPreview(replyToId) {
  if (!replyToId) return null;
  const row = await qOne(`SELECT m.id, m.text, u.display_name FROM messages m JOIN users u ON u.id = m.user_id WHERE m.id = $1`, [replyToId]);
  if (!row) return null;
  return { id: row.id, text: row.text, display_name: row.display_name };
}
async function reactionsSummary(messageId) {
  return q('SELECT emoji, COUNT(*) as count FROM message_reactions WHERE message_id = $1 GROUP BY emoji', [messageId]);
}
async function hydrateMessage(row) {
  return {
    ...row,
    reply_preview: await replyPreview(row.reply_to_id),
    reactions: await reactionsSummary(row.id),
  };
}

app.get('/api/messages', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.query.channelId);
  if (!channelId) return res.status(400).json({ error: 'Falta channelId' });
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });

  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const before = req.query.before ? parseInt(req.query.before) : Date.now() + 1;
  const oldestAllowed = Date.now() - RETENTION_MS;

  const rows = await q(`
    SELECT m.*, u.username, u.display_name, u.avatar_url
    FROM messages m JOIN users u ON u.id = m.user_id
    LEFT JOIN message_deleted_for mdf ON mdf.message_id = m.id AND mdf.user_id = $1
    WHERE m.channel_id = $2 AND m.created_at < $3 AND m.created_at > $4
      AND (m.scheduled_at IS NULL OR m.scheduled_at <= $5)
      AND mdf.message_id IS NULL
    ORDER BY m.created_at DESC
    LIMIT $6
  `, [req.user.id, channelId, before, oldestAllowed, Date.now(), limit]);

  const hydrated = await Promise.all(rows.reverse().map(hydrateMessage));
  res.json({ messages: hydrated });
});

async function insertAndBroadcastMessage({ channelId, userId, username, displayName, text, imageUrl, fileUrl, fileName, fileSize, voiceUrl, voiceDuration, lat, lng, replyToId, scheduledAt, selfDestructMinutes }) {
  const createdAt = Date.now();
  const selfDestructAt = selfDestructMinutes ? createdAt + selfDestructMinutes * 60 * 1000 : null;
  const info = await qOne(`
    INSERT INTO messages (channel_id, user_id, text, image_url, file_url, file_name, file_size, voice_url, voice_duration, location_lat, location_lng, reply_to_id, scheduled_at, self_destruct_at, created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id
  `, [channelId, userId, text || null, imageUrl || null, fileUrl || null, fileName || null, fileSize || null, voiceUrl || null, voiceDuration || null, lat || null, lng || null, replyToId || null, scheduledAt || null, selfDestructAt, createdAt]);

  const mentions = await extractMentions(text);
  for (const u of mentions) await pool.query('INSERT INTO message_mentions (message_id, mentioned_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [info.id, u.id]);

  const senderRow = await qOne('SELECT avatar_url FROM users WHERE id = $1', [userId]);
  const message = await hydrateMessage({
    id: info.id, channel_id: channelId, text: text || null, image_url: imageUrl || null,
    file_url: fileUrl || null, file_name: fileName || null, file_size: fileSize || null,
    voice_url: voiceUrl || null, voice_duration: voiceDuration || null,
    location_lat: lat || null, location_lng: lng || null, reply_to_id: replyToId || null,
    scheduled_at: scheduledAt || null, self_destruct_at: selfDestructAt, edited_at: null, pinned: 0,
    created_at: createdAt, username, display_name: displayName, avatar_url: senderRow ? senderRow.avatar_url : null,
  });

  if (!scheduledAt || scheduledAt <= Date.now()) {
    broadcastToChannel(channelId, { type: 'message', message });
  }
  return message;
}

app.post('/api/messages', authMiddleware, async (req, res) => {
  const { channelId, text, imageUrl, fileUrl, fileName, fileSize, replyToId, scheduledAt } = req.body || {};
  if (!channelId) return res.status(400).json({ error: 'Falta channelId' });
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const channel = await qOne('SELECT is_announcement_only FROM channels WHERE id = $1', [channelId]);
  if (channel && channel.is_announcement_only && !(await isChannelAdmin(channelId, req.user.id))) {
    return res.status(403).json({ error: 'Solo un admin puede publicar en este canal de anuncios' });
  }
  const cleanText = (text || '').trim().slice(0, MAX_TEXT_LENGTH);
  if (!cleanText && !imageUrl && !fileUrl) return res.status(400).json({ error: 'Mensaje vacio' });

  const message = await insertAndBroadcastMessage({
    channelId, userId: req.user.id, username: req.user.username, displayName: req.user.displayName,
    text: cleanText, imageUrl, fileUrl, fileName, fileSize, replyToId, scheduledAt,
  });
  res.json({ message });
});

app.patch('/api/messages/:id', authMiddleware, async (req, res) => {
  const { text } = req.body || {};
  const cleanText = (text || '').trim().slice(0, MAX_TEXT_LENGTH);
  if (!cleanText) return res.status(400).json({ error: 'El mensaje no puede quedar vacio' });
  const msg = await qOne('SELECT * FROM messages WHERE id = $1', [req.params.id]);
  if (!msg) return res.status(404).json({ error: 'Ese mensaje ya no existe' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Solo puedes editar tus propios mensajes' });

  await pool.query('INSERT INTO message_edit_history (message_id, old_text, edited_at) VALUES ($1, $2, $3)', [msg.id, msg.text, Date.now()]);
  const editedAt = Date.now();
  await pool.query('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [cleanText, editedAt, msg.id]);
  broadcastToChannel(msg.channel_id, { type: 'message_edited', channelId: msg.channel_id, id: msg.id, text: cleanText, edited_at: editedAt });
  res.json({ ok: true });
});

app.get('/api/messages/:id/history', authMiddleware, async (req, res) => {
  const msg = await qOne('SELECT channel_id FROM messages WHERE id = $1', [req.params.id]);
  if (!msg || !(await isMember(msg.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  const history = await q('SELECT old_text, edited_at FROM message_edit_history WHERE message_id = $1 ORDER BY edited_at ASC', [req.params.id]);
  res.json({ history });
});

app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  const msg = await qOne('SELECT * FROM messages WHERE id = $1', [req.params.id]);
  if (!msg) return res.status(404).json({ error: 'Ese mensaje ya no existe' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Solo puedes borrar tus propios mensajes' });
  await pool.query('DELETE FROM messages WHERE id = $1', [msg.id]);
  for (const url of [msg.image_url, msg.file_url, msg.voice_url]) {
    if (!url) continue;
    fs.unlink(path.join(UPLOADS_DIR, path.basename(url)), () => {});
  }
  broadcastToChannel(msg.channel_id, { type: 'message_deleted', channelId: msg.channel_id, id: msg.id });
  res.json({ ok: true });
});
app.post('/api/messages/:id/delete-for-me', authMiddleware, async (req, res) => {
  const msg = await qOne('SELECT channel_id FROM messages WHERE id = $1', [req.params.id]);
  if (!msg || !(await isMember(msg.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  await pool.query('INSERT INTO message_deleted_for (message_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

const ALLOWED_EMOJI = new Set(['👍', '❤️', '😂', '😮', '😢', '🙏']);
app.post('/api/messages/:id/react', authMiddleware, async (req, res) => {
  const { emoji } = req.body || {};
  if (!ALLOWED_EMOJI.has(emoji)) return res.status(400).json({ error: 'Emoji no permitido' });
  const msg = await qOne('SELECT channel_id FROM messages WHERE id = $1', [req.params.id]);
  if (!msg || !(await isMember(msg.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  await pool.query('INSERT INTO message_reactions (message_id, user_id, emoji, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING', [req.params.id, req.user.id, emoji, Date.now()]);
  const reactions = await reactionsSummary(req.params.id);
  broadcastToChannel(msg.channel_id, { type: 'reactions_updated', channelId: msg.channel_id, id: parseInt(req.params.id), reactions });
  res.json({ ok: true, reactions });
});
app.delete('/api/messages/:id/react/:emoji', authMiddleware, async (req, res) => {
  const msg = await qOne('SELECT channel_id FROM messages WHERE id = $1', [req.params.id]);
  if (!msg || !(await isMember(msg.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  await pool.query('DELETE FROM message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3', [req.params.id, req.user.id, req.params.emoji]);
  const reactions = await reactionsSummary(req.params.id);
  broadcastToChannel(msg.channel_id, { type: 'reactions_updated', channelId: msg.channel_id, id: parseInt(req.params.id), reactions });
  res.json({ ok: true, reactions });
});

app.post('/api/messages/:id/pin', authMiddleware, async (req, res) => {
  const msg = await qOne('SELECT channel_id FROM messages WHERE id = $1', [req.params.id]);
  if (!msg || !(await isChannelAdmin(msg.channel_id, req.user.id))) return res.status(403).json({ error: 'Solo un admin del grupo puede fijar mensajes' });
  await pool.query('UPDATE messages SET pinned = 1 WHERE id = $1', [req.params.id]);
  broadcastToChannel(msg.channel_id, { type: 'message_pinned', channelId: msg.channel_id, id: parseInt(req.params.id), pinned: true });
  res.json({ ok: true });
});
app.delete('/api/messages/:id/pin', authMiddleware, async (req, res) => {
  const msg = await qOne('SELECT channel_id FROM messages WHERE id = $1', [req.params.id]);
  if (!msg || !(await isChannelAdmin(msg.channel_id, req.user.id))) return res.status(403).json({ error: 'Solo un admin del grupo puede desfijar mensajes' });
  await pool.query('UPDATE messages SET pinned = 0 WHERE id = $1', [req.params.id]);
  broadcastToChannel(msg.channel_id, { type: 'message_pinned', channelId: msg.channel_id, id: parseInt(req.params.id), pinned: false });
  res.json({ ok: true });
});
app.get('/api/channels/:id/pinned-messages', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const rows = await q(`SELECT m.*, u.display_name FROM messages m JOIN users u ON u.id = m.user_id WHERE m.channel_id = $1 AND m.pinned = 1 ORDER BY m.created_at DESC`, [channelId]);
  res.json({ messages: rows });
});

app.post('/api/messages/:id/forward', authMiddleware, async (req, res) => {
  const { channelId } = req.body || {};
  const original = await qOne('SELECT * FROM messages WHERE id = $1', [req.params.id]);
  if (!original || !(await isMember(original.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces al grupo destino' });

  const message = await insertAndBroadcastMessage({
    channelId, userId: req.user.id, username: req.user.username, displayName: req.user.displayName,
    text: original.text, imageUrl: original.image_url, fileUrl: original.file_url, fileName: original.file_name, fileSize: original.file_size,
  });
  res.json({ message });
});

app.get('/api/search', authMiddleware, async (req, res) => {
  const query = (req.query.q || '').trim();
  if (query.length < 2) return res.status(400).json({ error: 'Escribe al menos 2 caracteres' });
  const rows = await q(`
    SELECT m.id, m.channel_id, m.text, m.created_at, u.display_name, c.name as channel_name
    FROM messages m
    JOIN users u ON u.id = m.user_id
    JOIN channels c ON c.id = m.channel_id
    JOIN channel_members cm ON cm.channel_id = c.id AND cm.user_id = $1
    WHERE m.text ILIKE $2 ORDER BY m.created_at DESC LIMIT 50
  `, [req.user.id, `%${query}%`]);
  res.json({ results: rows });
});

app.get('/api/channels/:id/export', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const channel = await qOne('SELECT name FROM channels WHERE id = $1', [channelId]);
  const rows = await q(`
    SELECT m.text, m.created_at, u.display_name FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.channel_id = $1 ORDER BY m.created_at ASC
  `, [channelId]);
  const lines = rows.map(r => `[${new Date(Number(r.created_at)).toLocaleString('es-MX')}] ${r.display_name}: ${r.text || '(archivo/imagen)'}`);
  res.json({ channelName: channel.name, text: lines.join('\n') });
});

// ---- Encuestas ----
app.post('/api/channels/:id/polls', authMiddleware, async (req, res) => {
  const channelId = parseInt(req.params.id);
  if (!(await isMember(channelId, req.user.id))) return res.status(403).json({ error: 'No perteneces a ese grupo' });
  const { question, options } = req.body || {};
  if (!question || !Array.isArray(options) || options.length < 2) return res.status(400).json({ error: 'Se necesita una pregunta y al menos 2 opciones' });

  const createdAt = Date.now();
  const pollInfo = await qOne('INSERT INTO polls (channel_id, question, created_by, created_at) VALUES ($1, $2, $3, $4) RETURNING id', [channelId, question.slice(0, 200), req.user.id, createdAt]);
  const optionIds = [];
  for (const text of options.slice(0, 10)) {
    const info = await qOne('INSERT INTO poll_options (poll_id, text) VALUES ($1, $2) RETURNING id', [pollInfo.id, String(text).slice(0, 100)]);
    optionIds.push({ id: info.id, text });
  }

  const message = await insertAndBroadcastMessage({
    channelId, userId: req.user.id, username: req.user.username, displayName: req.user.displayName,
    text: `📊 Encuesta: ${question}`,
  });
  await pool.query('UPDATE polls SET message_id = $1 WHERE id = $2', [message.id, pollInfo.id]);
  broadcastToChannel(channelId, { type: 'poll_created', channelId, poll: { id: pollInfo.id, question, options: optionIds, messageId: message.id } });
  res.json({ poll: { id: pollInfo.id, question, options: optionIds } });
});

app.get('/api/polls/:id', authMiddleware, async (req, res) => {
  const poll = await qOne('SELECT * FROM polls WHERE id = $1', [req.params.id]);
  if (!poll || !(await isMember(poll.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  const options = await q('SELECT * FROM poll_options WHERE poll_id = $1', [poll.id]);
  const votes = await q('SELECT option_id, COUNT(*) as count FROM poll_votes WHERE poll_id = $1 GROUP BY option_id', [poll.id]);
  const myVote = await qOne('SELECT option_id FROM poll_votes WHERE poll_id = $1 AND user_id = $2', [poll.id, req.user.id]);
  res.json({ poll, options, votes, myVote: myVote ? myVote.option_id : null });
});

app.post('/api/polls/:id/vote', authMiddleware, async (req, res) => {
  const { optionId } = req.body || {};
  const poll = await qOne('SELECT * FROM polls WHERE id = $1', [req.params.id]);
  if (!poll || !(await isMember(poll.channel_id, req.user.id))) return res.status(403).json({ error: 'No autorizado' });
  await pool.query(`
    INSERT INTO poll_votes (poll_id, option_id, user_id, voted_at) VALUES ($1, $2, $3, $4)
    ON CONFLICT (poll_id, user_id) DO UPDATE SET option_id = excluded.option_id, voted_at = excluded.voted_at
  `, [poll.id, optionId, req.user.id, Date.now()]);
  const votes = await q('SELECT option_id, COUNT(*) as count FROM poll_votes WHERE poll_id = $1 GROUP BY option_id', [poll.id]);
  broadcastToChannel(poll.channel_id, { type: 'poll_voted', channelId: poll.channel_id, pollId: poll.id, votes });
  res.json({ ok: true, votes });
});

// ---- Estados / historias (24 horas) ----
app.post('/api/stories', authMiddleware, async (req, res) => {
  const { text, imageUrl } = req.body || {};
  if (!text && !imageUrl) return res.status(400).json({ error: 'El estado no puede estar vacio' });
  const createdAt = Date.now();
  await pool.query('INSERT INTO messages (channel_id, user_id, text, image_url, self_destruct_at, created_at) VALUES (0, $1, $2, $3, $4, $5)',
    [req.user.id, (text || '').slice(0, 300), imageUrl || null, createdAt + 24 * 60 * 60 * 1000, createdAt]);
  res.json({ ok: true });
});
app.get('/api/stories', authMiddleware, async (req, res) => {
  const rows = await q(`
    SELECT m.id, m.text, m.image_url, m.created_at, m.self_destruct_at, u.display_name, u.avatar_url
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.channel_id = 0 AND m.self_destruct_at > $1 ORDER BY m.created_at DESC
  `, [Date.now()]);
  res.json({ stories: rows });
});

// ---- Servidor HTTP + WebSocket ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2 * 1024 * 1024 });

const clients = new Map();
let typingTimers = new Map();

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

  ws.on('message', async (raw) => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }

    if (data.type === 'auth') {
      try {
        const user = jwt.verify(data.token, JWT_SECRET);
        const dbUser = await qOne('SELECT avatar_url FROM users WHERE id = $1', [user.id]);
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
      if (!(await isMember(channelId, info.userId))) {
        ws.send(JSON.stringify({ type: 'join_error', error: 'No perteneces a ese grupo' }));
        return;
      }
      const prevChannel = info.channelId;
      info.channelId = channelId;
      if (prevChannel && prevChannel !== channelId) broadcastPresence(prevChannel);
      broadcastPresence(channelId);
      return;
    }

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

    if (data.type === 'call_offer' || data.type === 'call_answer' || data.type === 'call_ice' || data.type === 'call_end') {
      if (data.toUserId) sendToUser(data.toUserId, { ...data, fromUserId: info.userId, fromDisplayName: info.displayName });
      return;
    }

    if (data.type === 'message' && info.channelId && ((data.text && data.text.trim()) || data.imageUrl || data.fileUrl || data.voiceUrl || (data.lat && data.lng))) {
      const channelId = info.channelId;
      const channel = await qOne('SELECT is_announcement_only FROM channels WHERE id = $1', [channelId]);
      if (channel && channel.is_announcement_only && !(await isChannelAdmin(channelId, info.userId))) return;

      const cleanText = (data.text || '').trim().slice(0, MAX_TEXT_LENGTH);
      await insertAndBroadcastMessage({
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

// ---- Trabajos periodicos ----
async function releaseScheduledMessages() {
  const due = await q('SELECT * FROM messages WHERE scheduled_at IS NOT NULL AND scheduled_at <= $1', [Date.now()]);
  for (const m of due) {
    const user = await qOne('SELECT username, display_name, avatar_url FROM users WHERE id = $1', [m.user_id]);
    if (!user) continue;
    broadcastToChannel(m.channel_id, { type: 'message', message: await hydrateMessage({ ...m, username: user.username, display_name: user.display_name, avatar_url: user.avatar_url }) });
    await pool.query('UPDATE messages SET scheduled_at = NULL WHERE id = $1', [m.id]);
  }
}
async function cleanupSelfDestruct() {
  const due = await q('SELECT id, channel_id, image_url, file_url, voice_url FROM messages WHERE self_destruct_at IS NOT NULL AND self_destruct_at <= $1', [Date.now()]);
  for (const m of due) {
    await pool.query('DELETE FROM messages WHERE id = $1', [m.id]);
    for (const url of [m.image_url, m.file_url, m.voice_url]) {
      if (url) fs.unlink(path.join(UPLOADS_DIR, path.basename(url)), () => {});
    }
    if (m.channel_id !== 0) broadcastToChannel(m.channel_id, { type: 'message_deleted', channelId: m.channel_id, id: m.id });
  }
}
async function cleanupOldMessages() {
  const cutoff = Date.now() - RETENTION_MS;
  try {
    const oldOnes = await q('SELECT image_url, file_url, voice_url FROM messages WHERE created_at < $1 AND channel_id != 0', [cutoff]);
    const result = await pool.query('DELETE FROM messages WHERE created_at < $1 AND channel_id != 0', [cutoff]);
    if (result.rowCount > 0) {
      console.log(`Limpieza automatica: ${result.rowCount} mensaje(s) de mas de ${RETENTION_DAYS} dias eliminados.`);
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

// ---- Arranque: primero conecta la base de datos, luego levanta el servidor ----
initDb()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`Mensajeria interna backend escuchando en http://localhost:${PORT}`);
      console.log(`WebSocket disponible en ws://localhost:${PORT}/ws`);
      if (JWT_SECRET === 'CAMBIA_ESTE_SECRETO_ANTES_DE_PRODUCCION') {
        console.warn('\n⚠️  ADVERTENCIA DE SEGURIDAD: JWT_SECRET no esta configurado.\n');
      }
      if (ADMIN_KEY === 'CAMBIA_ESTA_CLAVE_DE_ADMIN') {
        console.warn('\n⚠️  ADVERTENCIA DE SEGURIDAD: ADMIN_KEY no esta configurado.\n');
      }
      cleanupOldMessages();
      setInterval(releaseScheduledMessages, 30 * 1000);
      setInterval(cleanupSelfDestruct, 60 * 1000);
      setInterval(cleanupOldMessages, 24 * 60 * 60 * 1000);
    });
  })
  .catch((err) => {
    console.error('❌ No se pudo conectar a la base de datos (Postgres/Neon). Revisa DATABASE_URL.', err);
    process.exit(1);
  });
