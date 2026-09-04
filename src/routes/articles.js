const express = require('express');
const { db } = require('../db/init');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// GET /api/articles  (lista pública)
router.get('/articles', (req, res) => {
  const rows = db.prepare('SELECT slug,title,body,author_id,private FROM articles WHERE private = 0').all();
  res.json({ articles: rows, articlesCount: rows.length });
});

module.exports = router;
