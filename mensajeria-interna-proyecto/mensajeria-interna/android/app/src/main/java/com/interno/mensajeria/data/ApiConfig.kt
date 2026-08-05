package com.interno.mensajeria.data

/**
 * Cambia BASE_URL por la direccion PUBLICA donde quede corriendo el backend
 * una vez desplegado (ver backend/README.md -> seccion "Desplegarlo en internet").
 *
 * Ejemplos:
 *  - "https://mensajeria-interna-backend.onrender.com/"  -> desplegado en Render
 *  - "https://tu-app.up.railway.app/"                     -> desplegado en Railway
 *  - "http://192.168.1.50:4000/"                          -> solo misma red local
 *  - "http://10.0.2.2:4000/"                              -> solo emulador local
 *
 * IMPORTANTE: si usas https:// aqui, WS_URL usara wss:// automaticamente
 * (necesario para que el WebSocket funcione con datos moviles/fuera de tu wifi).
 */
object ApiConfig {
    const val BASE_URL = "https://TU-BACKEND.onrender.com/"

    val WS_URL: String
        get() = BASE_URL.replaceFirst("https", "wss").replaceFirst("http", "ws") + "ws"
}
