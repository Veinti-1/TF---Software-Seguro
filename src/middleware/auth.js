const { verifyToken } = require('../auth');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Token ') ? header.slice(6)
              : header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ errors: { body: ['No token provided'] } });
  try {
    req.user = verifyToken(token);
    next();
  } catch (e) {
    return res.status(401).json({ errors: { body: ['Invalid token'] } });
  }
}

// [FIX A01:2021] RBAC: exige rol admin. Debe encadenarse DESPUÉS de requireAuth.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ errors: { body: ['Forbidden: se requiere rol admin'] } });
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
