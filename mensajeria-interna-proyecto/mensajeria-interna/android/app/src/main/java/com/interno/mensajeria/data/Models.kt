package com.interno.mensajeria.data

data class RegisterRequest(val username: String, val password: String, val displayName: String)
data class LoginRequest(val username: String, val password: String)
data class UserDto(val id: Int, val username: String, val displayName: String)
data class AuthResponse(val token: String, val user: UserDto)

data class MessageDto(
    val id: Long,
    val text: String,
    val created_at: Long,
    val username: String,
    val display_name: String
)
data class MessagesResponse(val messages: List<MessageDto>)
data class SendMessageRequest(val text: String)
data class SendMessageResponse(val message: MessageDto)
