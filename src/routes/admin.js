const express = require('express');
const { db } = require('../db/init');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// GET /api/admin/users  (panel administrativo)
// [VULN A01:2021 - Broken Access Control] Solo exige requireAuth, NO rol admin.
router.get('/admin/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id,username,email,role,tax_id FROM users').all();
  res.json({ users });
});

module.exports = router;
