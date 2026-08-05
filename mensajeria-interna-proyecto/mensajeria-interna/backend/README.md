# Backend — Mensajería Interna

Backend mínimo para la app de mensajería interna: registro/login con JWT,
historial de mensajes, y mensajería en tiempo real por WebSocket. Usa SQLite
(archivo local `mensajeria.db`), así que no necesitas instalar una base de
datos aparte.

## Requisitos
- Node.js 18 o superior

## Probarlo en tu computadora

```bash
cd backend
npm install
cp .env.example .env    # y edita JWT_SECRET
npm start
```

Queda en `http://localhost:4000` (REST) y `ws://localhost:4000/ws` (WebSocket).

## Endpoints REST

| Método | Ruta            | Auth | Descripción                          |
|--------|-----------------|------|---------------------------------------|
| POST   | /api/register   | No   | Crea usuario, devuelve token JWT      |
| POST   | /api/login      | No   | Devuelve token JWT                    |
| GET    | /api/messages   | Sí   | Historial del canal `general`         |
| POST   | /api/messages   | Sí   | Envía un mensaje (alternativa al WS)  |

Auth: header `Authorization: Bearer <token>`.

## WebSocket

1. Conectar a `wss://<tu-dominio>/ws` (o `ws://` en local sin HTTPS).
2. Primer mensaje enviado: `{"type":"auth","token":"<jwt>"}`.
3. Recibirás `{"type":"auth_ok"}` y a partir de ahí:
   - `{"type":"message", ...}` cuando llega un mensaje nuevo.
   - `{"type":"presence", "online": ["Nombre 1", "Nombre 2"]}` al cambiar quién está conectado.
4. Para enviar: `{"type":"message","text":"hola equipo"}`.

---

## Desplegarlo en internet (para que cualquier celular con datos se conecte)

La forma más simple, gratis para empezar: **Render**.

### Opción A — Render (recomendada, con `render.yaml` incluido)

1. Sube esta carpeta del proyecto a un repositorio de GitHub (puede ser privado).
2. Entra a [render.com](https://render.com) y crea una cuenta.
3. **New +** → **Blueprint** → conecta tu repo → Render detecta `render.yaml`
   automáticamente y configura todo (usa `rootDir: backend`).
4. Confirma el despliegue. En unos minutos te da una URL pública, por ejemplo:
   `https://mensajeria-interna-backend.onrender.com`
5. Copia esa URL y pégala en
   `android/app/src/main/java/com/interno/mensajeria/data/ApiConfig.kt`
   (`BASE_URL = "https://mensajeria-interna-backend.onrender.com/"`)
   y recompila el APK.
6. El archivo `mensajeria-interna.html` no necesita este backend — sigue
   funcionando por su cuenta con el almacenamiento del artefacto.

**Importante — límites del plan gratis de Render:**
- El servicio "duerme" tras ~15 min sin uso; el primer mensaje después de
  eso puede tardar unos segundos en responder mientras despierta.
- El disco es efímero: si Render reinicia o vuelve a desplegar el
  servicio, se pierde `mensajeria.db` (el historial de mensajes y
  usuarios). Para uso interno ligero suele ser aceptable; si necesitas que
  el historial persista siempre, hay que pasar a un plan pago con disco
  persistente, o mover los datos a una base externa (ej. Postgres gestionado).

### Opción B — Railway

Mismo backend, sin cambiar nada de código:
1. [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**.
2. Selecciona la carpeta `backend` como root.
3. Agrega la variable de entorno `JWT_SECRET`.
4. Railway te da una URL pública (`https://tu-app.up.railway.app`) — úsala
   igual que en la Opción A.

### Opción C — Tu propio servidor / VPS

Incluí un `Dockerfile`. En cualquier VPS con Docker:

```bash
docker build -t mensajeria-backend .
docker run -d -p 4000:4000 -e JWT_SECRET=tu-secreto-largo mensajeria-backend
```

Luego pon un proxy (Nginx/Caddy) delante con HTTPS para tu dominio, y usa
esa URL (`https://chat.tuempresa.com/`) en `ApiConfig.kt`. Esta opción sí
te da disco persistente de verdad (el archivo `mensajeria.db` vive en el
propio VPS).
