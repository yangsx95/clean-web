package app.cleanweb.android.vpn

import android.content.Context
import app.cleanweb.android.model.CleanWebState
import java.io.File
import java.security.MessageDigest

class MihomoAndroidRunner(private val context: Context) {
    private var process: Process? = null

    fun start(state: CleanWebState): File {
        stop()
        val runtime = File(context.filesDir, "mihomo").also { it.mkdirs() }
        val binary = installedBinary()
        val config = File(runtime, "config.yaml")
        config.writeText(MihomoAndroidConfig.build(state), Charsets.UTF_8)
        val log = File(runtime, "mihomo.log")
        process = ProcessBuilder(binary.absolutePath, "-d", runtime.absolutePath, "-f", config.absolutePath)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(log))
            .start()
        return log
    }

    fun stop() {
        process?.destroy()
        process = null
    }

    private fun installedBinary(): File {
        val binary = File(context.applicationInfo.nativeLibraryDir, "libmihomo.so")
        require(binary.exists() && binary.length() > 0) {
            "当前设备 ABI 缺少随包分发的 Mihomo 安卓内核。"
        }
        require(sha256(binary) == MIHOMO_ANDROID_ARM64_SHA256) {
            "Mihomo 安卓内核校验失败。"
        }
        return binary
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    companion object {
        private const val MIHOMO_ANDROID_ARM64_SHA256 =
            "fe85504f9a8d9f4e92759de5634fe513b18cce0f259fe627e1a3fa56d886ecfa"
    }
}
