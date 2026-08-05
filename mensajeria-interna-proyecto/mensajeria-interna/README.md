# Mensajería Interna — Proyecto completo

Contiene dos partes:

```
backend/    Node.js + Express + SQLite + WebSocket (servidor de mensajes)
android/    App Android nativa (Kotlin + Jetpack Compose) que habla con el backend
```

Usarás **las dos versiones a la vez**:

- `mensajeria-interna.html` — funciona ya mismo desde el navegador de
  cualquier celular, solo con internet, sin instalar nada.
- La app Android nativa (`android/`) — una vez que despliegues `backend/`
  en internet (ver `backend/README.md`), cualquier celular con datos podrá
  usarla también, sin depender de estar en la misma red.

## 1. Levantar el backend (en tu computadora, para probar)

```bash
cd backend
npm install
cp .env.example .env   # edita JWT_SECRET
npm start
```

Queda en `http://localhost:4000`. Para que funcione desde cualquier
celular por internet (no solo en tu red local), tienes que **desplegarlo**
— instrucciones paso a paso (Render, Railway o tu propio servidor) en
`backend/README.md`, sección "Desplegarlo en internet".

## 2. Compilar el APK

Necesitas [Android Studio](https://developer.android.com/studio) (gratis).

1. Abre Android Studio → **Open** → selecciona la carpeta `android/`.
2. Deja que sincronice Gradle (la primera vez descarga dependencias, necesita internet).
3. Antes de compilar, en
   `android/app/src/main/java/com/interno/mensajeria/data/ApiConfig.kt`
   cambia `BASE_URL` por la URL pública que te dio Render/Railway/tu
   servidor al desplegar el backend (paso anterior). No dejes
   `TU-BACKEND.onrender.com` sin reemplazar.
4. Menú **Build → Build App Bundle(s) / APK(s) → Build APK(s)**.
5. El APK queda en `android/app/build/outputs/apk/debug/app-debug.apk`.
   Cópialo al celular e instálalo (activa "Instalar apps de origen
   desconocido" ya que no está en Play Store — es una app interna).

Para una versión firmada de release (recomendable para distribución
interna real, no solo pruebas), usa **Build → Generate Signed Bundle / APK**
y sigue el asistente para crear tu propio keystore.

## Qué incluye la app

- Registro / login con usuario y contraseña.
- Un canal general compartido por todo el equipo.
- Mensajes en tiempo real vía WebSocket.
- Lista de quién está en línea.
- Historial de mensajes al entrar.

## Qué NO incluye (siguiente nivel si lo necesitas)

- Múltiples canales o mensajes directos 1 a 1.
- Notificaciones push cuando la app está cerrada.
- Envío de imágenes o archivos.
- Cifrado extremo a extremo (los mensajes viajan protegidos por HTTPS/WSS
  si configuras el backend con TLS, pero el servidor puede leerlos).

Dímelo si quieres que agregue alguna de estas.
