const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('\n❌ Falta la variable de entorno DATABASE_URL (la cadena de conexion de Neon).\n');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Neon exige SSL
});

// Todas las fechas se guardan como BIGINT (milisegundos desde epoch, igual
// que Date.now() en JS) en vez de TIMESTAMP de Postgres, para no tocar la
// logica de fechas que ya existia con SQLite.
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      avatar_url TEXT,
      last_seen_at BIGINT,
      dnd_start TEXT,
      dnd_end TEXT,
      dnd_enabled INTEGER DEFAULT 0,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS channels (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      photo_url TEXT,
      description TEXT,
      is_announcement_only INTEGER DEFAULT 0,
      created_by INTEGER,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS channel_members (
      channel_id INTEGER NOT NULL REFERENCES channels(id),
      user_id INTEGER NOT NULL REFERENCES users(id),
      role TEXT NOT NULL DEFAULT 'member',
      joined_at BIGINT NOT NULL,
      PRIMARY KEY (channel_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS channel_pinned (
      channel_id INTEGER NOT NULL, user_id INTEGER NOT NULL, pinned_at BIGINT NOT NULL,
      PRIMARY KEY (channel_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS channel_archived (
      channel_id INTEGER NOT NULL, user_id INTEGER NOT NULL, archived_at BIGINT NOT NULL,
      PRIMARY KEY (channel_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS channel_muted (
      channel_id INTEGER NOT NULL, user_id INTEGER NOT NULL, muted_at BIGINT NOT NULL,
      PRIMARY KEY (channel_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      channel_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      text TEXT,
      image_url TEXT, file_url TEXT, file_name TEXT, file_size INTEGER,
      voice_url TEXT, voice_duration INTEGER,
      location_lat DOUBLE PRECISION, location_lng DOUBLE PRECISION,
      reply_to_id INTEGER,
      edited_at BIGINT, scheduled_at BIGINT, self_destruct_at BIGINT,
      pinned INTEGER DEFAULT 0,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS message_reactions (
      id SERIAL PRIMARY KEY, message_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL, created_at BIGINT NOT NULL,
      UNIQUE(message_id, user_id, emoji)
    );
    CREATE TABLE IF NOT EXISTS message_deleted_for (
      message_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (message_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS message_edit_history (
      id SERIAL PRIMARY KEY, message_id INTEGER NOT NULL, old_text TEXT, edited_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS message_mentions (
      message_id INTEGER NOT NULL, mentioned_user_id INTEGER NOT NULL, PRIMARY KEY (message_id, mentioned_user_id)
    );

    CREATE TABLE IF NOT EXISTS read_state (
      channel_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      last_read_message_id INTEGER NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL,
      PRIMARY KEY (channel_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, platform TEXT NOT NULL,
      endpoint TEXT, p256dh TEXT, auth TEXT, fcm_token TEXT, created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS polls (
      id SERIAL PRIMARY KEY, channel_id INTEGER NOT NULL, message_id INTEGER,
      question TEXT NOT NULL, created_by INTEGER NOT NULL, created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS poll_options (
      id SERIAL PRIMARY KEY, poll_id INTEGER NOT NULL, text TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id INTEGER NOT NULL, option_id INTEGER NOT NULL, user_id INTEGER NOT NULL, voted_at BIGINT NOT NULL,
      PRIMARY KEY (poll_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS deletion_requests (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id), requested_at BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_channel_created ON messages(channel_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
    CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions(message_id);
  `);

  let general = (await pool.query('SELECT id FROM channels WHERE name = $1', ['general'])).rows[0];
  if (!general) {
    const info = await pool.query(
      'INSERT INTO channels (name, created_by, created_at) VALUES ($1, $2, $3) RETURNING id',
      ['general', null, Date.now()]
    );
    general = { id: info.rows[0].id };
  }
  const allUsers = (await pool.query('SELECT id FROM users')).rows;
  for (const u of allUsers) {
    await pool.query(
      "INSERT INTO channel_members (channel_id, user_id, role, joined_at) VALUES ($1, $2, 'member', $3) ON CONFLICT DO NOTHING",
      [general.id, u.id, Date.now()]
    );
  }

  console.log('Base de datos (Postgres/Neon) lista.');
}

module.exports = { pool, initDb };
