const express = require('express');
const bcrypt = require('bcryptjs');
const { db } = require('../db/init');
const { signToken } = require('../auth');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// POST /api/users/login
// [FIX A03:2021] Consulta parametrizada (prepared statement) + verificación real de password.
router.post('/users/login', (req, res) => {
  const { email, password } = (req.body && req.body.user) || {};
  if (!email || !password) return res.status(422).json({ errors: { body: ['email y password requeridos'] } });
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email); // <-- parametrizada
  if (!row || !bcrypt.compareSync(password, row.password)) {
    return res.status(401).json({ errors: { body: ['Invalid credentials'] } });
  }
  const token = signToken({ id: row.id, username: row.username, role: row.role });
  res.json({ user: { email: row.email, username: row.username, role: row.role, token } });
});

router.get('/user', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id,username,email,role,bio FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: u });
});

// GET /api/accounts/:id
// [FIX API1:2023 BOLA] Validación de propiedad contextual: solo la propia cuenta (o admin).
router.get('/accounts/:id', requireAuth, (req, res) => {
  const requestedId = Number(req.params.id);
  if (req.user.id !== requestedId && req.user.role !== 'admin') {
    return res.status(403).json({ errors: { body: ['Forbidden: no eres propietario del recurso'] } });
  }
  const acct = db.prepare(
    'SELECT id,username,email,full_name,phone,tax_id FROM users WHERE id = ?'
  ).get(requestedId);
  if (!acct) return res.status(404).json({ errors: { body: ['Not found'] } });
  res.json({ account: acct });
});

module.exports = router;
