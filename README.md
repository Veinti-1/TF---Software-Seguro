# Conduit Secure SDLC — Proyecto Final

API REST estilo RealWorld (Conduit) en Node.js/Express + SQLite con JWT.
Base de código para el ciclo de Secure SDLC: threat modeling, pentest, remediación y DevSecOps.

## Ejecutar
```
npm install
npm start        # http://localhost:3000
```

## Estructura
- `src/` código de la API
- `poc/` scripts de prueba de concepto (PoC) de las 4 vulnerabilidades
- `.github/workflows/devsecops.yml` pipeline CI/CD con quality gates

## Historial
- Commit `baseline vulnerable`: contiene las 4 vulnerabilidades obligatorias.
- Commits de remediación: correcciones por vector.
