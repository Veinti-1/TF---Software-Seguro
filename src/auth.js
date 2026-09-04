const jwt = require('jsonwebtoken');

// [FIX] Secreto desde variable de entorno (fallback solo para desarrollo local).
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';

// [FIX API2:2023] Firma HS256 con expiración obligatoria.
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
}

// [FIX API2:2023] Verifica firma forzando HS256 y exigiendo exp (rechaza alg:none y forjados).
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], maxAge: '1h' });
}

module.exports = { signToken, verifyToken, JWT_SECRET };
