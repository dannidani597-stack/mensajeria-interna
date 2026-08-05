package com.interno.mensajeria.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Amber = Color(0xFFFF8A3D)
private val AmberContainerLight = Color(0xFFFFE0C2)
private val AmberContainerDark = Color(0xFF4A3220)

private val LightColors = lightColorScheme(
    primary = Amber,
    primaryContainer = AmberContainerLight,
)

private val DarkColors = darkColorScheme(
    primary = Amber,
    primaryContainer = AmberContainerDark,
)

@Composable
fun MensajeriaInternaTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) DarkColors else LightColors
    MaterialTheme(colorScheme = colors, content = content)
}
