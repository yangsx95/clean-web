package app.cleanweb.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import app.cleanweb.android.ui.CleanWebApp
import app.cleanweb.android.ui.theme.CleanWebTheme
import app.cleanweb.android.vpn.CleanWebVpnService
import app.cleanweb.android.vpn.VpnStatus

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            CleanWebTheme {
                var status by remember { mutableStateOf(VpnStatus.Idle) }
                val vpnPermissionLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == RESULT_OK) {
                        CleanWebVpnService.start(this)
                        status = VpnStatus.Running
                    } else {
                        status = VpnStatus.PermissionDenied
                    }
                }

                LaunchedEffect(Unit) {
                    status = if (CleanWebVpnService.isRunning) VpnStatus.Running else VpnStatus.Idle
                }

                CleanWebApp(
                    status = status,
                    onStartProtection = {
                        val permissionIntent: Intent? = VpnService.prepare(this)
                        if (permissionIntent == null) {
                            CleanWebVpnService.start(this)
                            status = VpnStatus.Running
                        } else {
                            vpnPermissionLauncher.launch(permissionIntent)
                        }
                    },
                    onStopProtection = {
                        CleanWebVpnService.stop(this)
                        status = VpnStatus.Idle
                    }
                )
            }
        }
    }
}
