package com.interno.mensajeria.data

import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.Response as OkResponse

/**
 * Cliente WebSocket para mensajes/presencia en tiempo real.
 * Primer mensaje enviado siempre es de autenticacion (ver backend/README.md).
 */
class ChatSocket(
    private val token: String,
    private val onMessage: (MessageDto) -> Unit,
    private val onPresence: (List<String>) -> Unit,
    private val onAuthError: () -> Unit,
) {
    private val gson = Gson()
    private val client = OkHttpClient()
    private var socket: WebSocket? = null

    fun connect() {
        val request = Request.Builder().url(ApiConfig.WS_URL).build()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: OkResponse) {
                val auth = JsonObject().apply {
                    addProperty("type", "auth")
                    addProperty("token", token)
                }
                webSocket.send(gson.toJson(auth))
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val obj = gson.fromJson(text, JsonObject::class.java)
                when (obj.get("type")?.asString) {
                    "message" -> {
                        val msg = gson.fromJson(obj.get("message"), MessageDto::class.java)
                        onMessage(msg)
                    }
                    "presence" -> {
                        val arr = obj.getAsJsonArray("online")
                        onPresence(arr.map { it.asString })
                    }
                    "auth_error" -> onAuthError()
                }
            }
        })
    }

    fun send(text: String) {
        val obj = JsonObject().apply {
            addProperty("type", "message")
            addProperty("text", text)
        }
        socket?.send(gson.toJson(obj))
    }

    fun close() {
        socket?.close(1000, "cierre normal")
    }
}
