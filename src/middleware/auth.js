const { verifyToken } = require('../auth');

// Requiere estar autenticado (token válido).
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Token ') ? header.slice(6)
              : header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ errors: { body: ['No token provided'] } });
  try {
    req.user = verifyToken(token);
    next();
  } catch (e) {
    return res.status(401).json({ errors: { body: ['Invalid token: ' + e.message] } });
  }
}

// [VULN A01] NO existe verificación de rol admin: los endpoints admin solo usan requireAuth.
module.exports = { requireAuth };
