const jwt = require('jsonwebtoken');
const config = require('./config');

// [VULN - Secreto hardcodeado] importado desde config.js (ver Gitleaks).
const JWT_SECRET = config.jwtSecret;

// [VULN API2:2023] Emite tokens SIN expiración (replay indefinido).
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET); // falta expiresIn
}

// [VULN API2:2023] "Verifica" con jwt.decode(): NO comprueba la firma.
// => acepta tokens alg:none y cualquier token forjado sin conocer el secreto.
function verifyToken(token) {
  const decoded = jwt.decode(token); // <-- NO valida firma ni algoritmo
  if (!decoded) throw new Error('malformed token');
  return decoded;
}

module.exports = { signToken, verifyToken, JWT_SECRET };
