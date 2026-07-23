package app.cleanweb.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val CleanWebColorScheme = lightColorScheme(
    primary = Color(0xFF146C5F),
    onPrimary = Color.White,
    secondary = Color(0xFF4C635F),
    background = Color(0xFFFAFDFC),
    surface = Color(0xFFFAFDFC),
    onBackground = Color(0xFF191C1B),
    onSurface = Color(0xFF191C1B),
    onSurfaceVariant = Color(0xFF3F4946)
)

@Composable
fun CleanWebTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = CleanWebColorScheme,
        content = content
    )
}
