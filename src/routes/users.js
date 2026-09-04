const express = require('express');
const bcrypt = require('bcryptjs');
const { db } = require('../db/init');
const { signToken } = require('../auth');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// POST /api/users/login
// [VULN A03:2021 - SQL Injection] Query construida por concatenación de strings.
router.post('/users/login', (req, res) => {
  const { email, password } = (req.body && req.body.user) || {};
  const sql = `SELECT * FROM users WHERE email = '${email}'`; // <-- INYECTABLE
  let row;
  try {
    row = db.prepare(sql).get();
  } catch (e) {
    return res.status(500).json({ errors: { body: ['SQL error: ' + e.message] } });
  }
  if (!row) return res.status(401).json({ errors: { body: ['Invalid credentials'] } });
  // Con bypass por inyección el atacante entra sin conocer el password real
  const ok = bcrypt.compareSync(password || '', row.password);
  if (!ok && !email.includes("'")) {
    return res.status(401).json({ errors: { body: ['Invalid credentials'] } });
  }
  const token = signToken({ id: row.id, username: row.username, role: row.role });
  res.json({ user: { email: row.email, username: row.username, role: row.role, token } });
});

// GET /api/user  (perfil propio)
router.get('/user', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id,username,email,role,bio FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: u });
});

// GET /api/accounts/:id  (datos de cuenta / PII)
// [VULN API1:2023 - BOLA/IDOR] No valida que :id pertenezca al usuario autenticado.
router.get('/accounts/:id', requireAuth, (req, res) => {
  const acct = db.prepare(
    'SELECT id,username,email,full_name,phone,tax_id FROM users WHERE id = ?'
  ).get(req.params.id);
  if (!acct) return res.status(404).json({ errors: { body: ['Not found'] } });
  res.json({ account: acct }); // devuelve PII de cualquier id
});

module.exports = router;
