const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, '..', '..', 'conduit.db'));

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      bio TEXT DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user',
      -- PII / datos sensibles (no deben exponerse a terceros)
      full_name TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      tax_id TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      author_id INTEGER NOT NULL,
      private INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(author_id) REFERENCES users(id)
    );
  `);

  const count = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (count === 0) {
    const insert = db.prepare(
      'INSERT INTO users (username,email,password,role,full_name,phone,tax_id,bio) VALUES (?,?,?,?,?,?,?,?)'
    );
    insert.run('admin', 'admin@conduit.io', bcrypt.hashSync('S3cur3-Adm!n', 10), 'admin',
               'Alice Admin', '+502-5555-0001', 'CF-9001-ADMIN', 'Site administrator');
    insert.run('alice', 'alice@corp.io', bcrypt.hashSync('alicePass1', 10), 'user',
               'Alice Rivera', '+502-5555-1234', 'CUI-2985-1111', 'Regular user Alice');
    insert.run('victor', 'victor@corp.io', bcrypt.hashSync('victorPass1', 10), 'user',
               'Victor Lopez', '+502-5555-9876', 'CUI-7410-2222', 'Victim user Victor');

    const insA = db.prepare('INSERT INTO articles (slug,title,body,author_id,private) VALUES (?,?,?,?,?)');
    insA.run('welcome-to-conduit', 'Welcome to Conduit', 'Public article body', 2, 0);
    insA.run('victor-private-notes', 'Victor Private Notes', 'Confidential business plan of Victor', 3, 1);
  }
}

module.exports = { db, initDb };
