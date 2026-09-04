const express = require('express');
const { db } = require('../db/init');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const router = express.Router();

// GET /api/admin/users
// [FIX A01:2021] Doble control: autenticación + autorización por rol (RBAC).
router.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id,username,email,role,tax_id FROM users').all();
  res.json({ users });
});

module.exports = router;
