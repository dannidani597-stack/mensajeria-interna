package com.interno.mensajeria

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.interno.mensajeria.data.ApiService
import com.interno.mensajeria.data.ChatSocket
import com.interno.mensajeria.data.LoginRequest
import com.interno.mensajeria.data.MessageDto
import com.interno.mensajeria.data.RegisterRequest
import kotlinx.coroutines.launch

class ChatViewModel : ViewModel() {
    private val api = ApiService.create()
    private var socket: ChatSocket? = null

    var token = mutableStateOf<String?>(null)
        private set
    var displayName = mutableStateOf<String?>(null)
        private set
    var authError = mutableStateOf<String?>(null)
        private set
    var loading = mutableStateOf(false)
        private set

    val messages = mutableStateListOf<MessageDto>()
    val online = mutableStateListOf<String>()

    fun login(username: String, password: String) = viewModelScope.launch {
        loading.value = true
        authError.value = null
        try {
            val res = api.login(LoginRequest(username, password))
            if (res.isSuccessful && res.body() != null) {
                onAuthed(res.body()!!.token, res.body()!!.user.displayName)
            } else {
                authError.value = "Usuario o contraseña incorrectos"
            }
        } catch (e: Exception) {
            authError.value = "No se pudo conectar al servidor: ${e.message}"
        } finally {
            loading.value = false
        }
    }

    fun register(username: String, password: String, name: String) = viewModelScope.launch {
        loading.value = true
        authError.value = null
        try {
            val res = api.register(RegisterRequest(username, password, name))
            if (res.isSuccessful && res.body() != null) {
                onAuthed(res.body()!!.token, res.body()!!.user.displayName)
            } else {
                authError.value = "No se pudo crear la cuenta (¿usuario ya existe?)"
            }
        } catch (e: Exception) {
            authError.value = "No se pudo conectar al servidor: ${e.message}"
        } finally {
            loading.value = false
        }
    }

    private fun onAuthed(t: String, name: String) {
        token.value = t
        displayName.value = name
        loadHistory()
        connectSocket()
    }

    private fun loadHistory() = viewModelScope.launch {
        val t = token.value ?: return@launch
        try {
            val res = api.getMessages("Bearer $t")
            if (res.isSuccessful && res.body() != null) {
                messages.clear()
                messages.addAll(res.body()!!.messages)
            }
        } catch (_: Exception) { /* se reintenta al reconectar el socket */ }
    }

    private fun connectSocket() {
        val t = token.value ?: return
        socket = ChatSocket(
            token = t,
            onMessage = { msg -> messages.add(msg) },
            onPresence = { names ->
                online.clear()
                online.addAll(names)
            },
            onAuthError = { logout() }
        )
        socket?.connect()
    }

    fun send(text: String) {
        if (text.isBlank()) return
        // Enviamos solo por WebSocket: el servidor hace broadcast a todos,
        // incluido este mismo cliente, así que no hace falta duplicar por REST.
        socket?.send(text.trim())
    }

    fun logout() {
        socket?.close()
        socket = null
        token.value = null
        displayName.value = null
        messages.clear()
        online.clear()
    }

    override fun onCleared() {
        socket?.close()
        super.onCleared()
    }
}
