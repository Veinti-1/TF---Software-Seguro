// Helper: ejecuta una petición y devuelve un registro de evidencia estructurado.
const BASE = process.env.BASE || 'http://localhost:3000';
async function call({ label, method='GET', path, headers={}, body }) {
  const opts = { method, headers: { ...headers } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(BASE + path, opts);
  let json; const text = await res.text();
  try { json = JSON.parse(text); } catch { json = text; }
  return {
    label,
    request: { method, url: BASE + path, headers: opts.headers, body: body ?? null },
    response: { status: res.status, statusText: res.statusText, body: json },
  };
}
module.exports = { call, BASE };
