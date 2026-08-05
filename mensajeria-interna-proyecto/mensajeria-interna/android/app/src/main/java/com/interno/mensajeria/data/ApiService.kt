package com.interno.mensajeria.data

import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Query

interface ApiService {
    @POST("api/register")
    suspend fun register(@Body body: RegisterRequest): Response<AuthResponse>

    @POST("api/login")
    suspend fun login(@Body body: LoginRequest): Response<AuthResponse>

    @GET("api/messages")
    suspend fun getMessages(
        @Header("Authorization") bearer: String,
        @Query("limit") limit: Int = 50
    ): Response<MessagesResponse>

    @POST("api/messages")
    suspend fun sendMessage(
        @Header("Authorization") bearer: String,
        @Body body: SendMessageRequest
    ): Response<SendMessageResponse>

    companion object {
        fun create(): ApiService {
            return Retrofit.Builder()
                .baseUrl(ApiConfig.BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(ApiService::class.java)
        }
    }
}
