const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'mensajeria.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_by INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS channel_members (
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, user_id),
    FOREIGN KEY(channel_id) REFERENCES channels(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    text TEXT,
    image_url TEXT,
    file_url TEXT,
    file_name TEXT,
    file_size INTEGER,
    edited_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(channel_id) REFERENCES channels(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS deletion_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    requested_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  -- Acelera el historial por canal (WHERE channel_id = ? ORDER BY created_at)
  -- y la limpieza automatica de mensajes de mas de 40 dias (WHERE created_at < ?).
  -- Sin esto, ambas consultas recorren la tabla completa; con pocos cientos
  -- de mensajes no se nota, pero evita que se vuelva lento cuando crezca.
  CREATE INDEX IF NOT EXISTS idx_messages_channel_created ON messages(channel_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
`);

// Migraciones simples para bases de datos que ya existian antes de estos campos.
const messageCols = db.prepare("PRAGMA table_info(messages)").all().map(c => c.name);
for (const col of ['image_url', 'file_url', 'file_name']) {
  if (!messageCols.includes(col)) db.exec(`ALTER TABLE messages ADD COLUMN ${col} TEXT`);
}
if (!messageCols.includes('file_size')) {
  db.exec('ALTER TABLE messages ADD COLUMN file_size INTEGER');
}
if (!messageCols.includes('edited_at')) {
  db.exec('ALTER TABLE messages ADD COLUMN edited_at INTEGER');
}
const channelCols = db.prepare("PRAGMA table_info(channels)").all().map(c => c.name);
if (!channelCols.includes('created_by')) {
  db.exec('ALTER TABLE channels ADD COLUMN created_by INTEGER');
}
const userCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userCols.includes('avatar_url')) {
  db.exec('ALTER TABLE users ADD COLUMN avatar_url TEXT');
}

// Asegura que exista el canal "general" (abierto: todos los usuarios son miembros).
let general = db.prepare('SELECT id FROM channels WHERE name = ?').get('general');
if (!general) {
  const info = db.prepare('INSERT INTO channels (name, created_by, created_at) VALUES (?, ?, ?)').run('general', null, Date.now());
  general = { id: info.lastInsertRowid };
}

// Cualquier usuario que no sea miembro de "general" todavia, se agrega
// (cubre usuarios creados antes de que existiera el sistema de membresias).
const allUsers = db.prepare('SELECT id FROM users').all();
const addMember = db.prepare('INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)');
for (const u of allUsers) {
  addMember.run(general.id, u.id, Date.now());
}

module.exports = db;
