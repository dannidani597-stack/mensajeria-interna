package com.interno.mensajeria

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import com.interno.mensajeria.ui.ChatScreen
import com.interno.mensajeria.ui.LoginScreen
import com.interno.mensajeria.ui.theme.MensajeriaInternaTheme

class MainActivity : ComponentActivity() {
    private val vm: ChatViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MensajeriaInternaTheme {
                val token by vm.token
                if (token == null) LoginScreen(vm) else ChatScreen(vm)
            }
        }
    }
}
