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
    last_seen_at INTEGER,
    dnd_start TEXT,
    dnd_end TEXT,
    dnd_enabled INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    photo_url TEXT,
    description TEXT,
    is_announcement_only INTEGER DEFAULT 0,
    created_by INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS channel_members (
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, user_id),
    FOREIGN KEY(channel_id) REFERENCES channels(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS channel_pinned (
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    pinned_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS channel_archived (
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    archived_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS channel_muted (
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    muted_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, user_id)
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
    voice_url TEXT,
    voice_duration INTEGER,
    location_lat REAL,
    location_lng REAL,
    reply_to_id INTEGER,
    edited_at INTEGER,
    scheduled_at INTEGER,
    self_destruct_at INTEGER,
    pinned INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(channel_id) REFERENCES channels(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(reply_to_id) REFERENCES messages(id)
  );

  CREATE TABLE IF NOT EXISTS message_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(message_id, user_id, emoji)
  );

  CREATE TABLE IF NOT EXISTS message_deleted_for (
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (message_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS message_edit_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    old_text TEXT,
    edited_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS message_mentions (
    message_id INTEGER NOT NULL,
    mentioned_user_id INTEGER NOT NULL,
    PRIMARY KEY (message_id, mentioned_user_id)
  );

  CREATE TABLE IF NOT EXISTS read_state (
    channel_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    last_read_message_id INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (channel_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    endpoint TEXT,
    p256dh TEXT,
    auth TEXT,
    fcm_token TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS polls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER NOT NULL,
    message_id INTEGER,
    question TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS poll_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id INTEGER NOT NULL,
    text TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS poll_votes (
    poll_id INTEGER NOT NULL,
    option_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    voted_at INTEGER NOT NULL,
    PRIMARY KEY (poll_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS deletion_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    requested_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_channel_created ON messages(channel_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
  CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions(message_id);
`);

// Migraciones simples para bases de datos que ya existian antes de estos campos.
function ensureColumn(table, col, type) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`);
}
ensureColumn('messages', 'image_url', 'TEXT');
ensureColumn('messages', 'file_url', 'TEXT');
ensureColumn('messages', 'file_name', 'TEXT');
ensureColumn('messages', 'file_size', 'INTEGER');
ensureColumn('messages', 'edited_at', 'INTEGER');
ensureColumn('messages', 'voice_url', 'TEXT');
ensureColumn('messages', 'voice_duration', 'INTEGER');
ensureColumn('messages', 'location_lat', 'REAL');
ensureColumn('messages', 'location_lng', 'REAL');
ensureColumn('messages', 'reply_to_id', 'INTEGER');
ensureColumn('messages', 'scheduled_at', 'INTEGER');
ensureColumn('messages', 'self_destruct_at', 'INTEGER');
ensureColumn('messages', 'pinned', 'INTEGER DEFAULT 0');
ensureColumn('channels', 'created_by', 'INTEGER');
ensureColumn('channels', 'photo_url', 'TEXT');
ensureColumn('channels', 'description', 'TEXT');
ensureColumn('channels', 'is_announcement_only', 'INTEGER DEFAULT 0');
ensureColumn('channel_members', 'role', "TEXT NOT NULL DEFAULT 'member'");
ensureColumn('users', 'avatar_url', 'TEXT');
ensureColumn('users', 'last_seen_at', 'INTEGER');
ensureColumn('users', 'dnd_start', 'TEXT');
ensureColumn('users', 'dnd_end', 'TEXT');
ensureColumn('users', 'dnd_enabled', 'INTEGER DEFAULT 0');

// Asegura que exista el canal "general" (abierto: todos los usuarios son miembros).
let general = db.prepare('SELECT id FROM channels WHERE name = ?').get('general');
if (!general) {
  const info = db.prepare('INSERT INTO channels (name, created_by, created_at) VALUES (?, ?, ?)').run('general', null, Date.now());
  general = { id: info.lastInsertRowid };
}

// Cualquier usuario que no sea miembro de "general" todavia, se agrega.
const allUsers = db.prepare('SELECT id FROM users').all();
const addMember = db.prepare("INSERT OR IGNORE INTO channel_members (channel_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)");
for (const u of allUsers) {
  addMember.run(general.id, u.id, Date.now());
}

module.exports = db;
