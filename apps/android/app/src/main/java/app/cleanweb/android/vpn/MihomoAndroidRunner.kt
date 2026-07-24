package app.cleanweb.android.vpn

import android.content.Context
import app.cleanweb.android.model.CleanWebState
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
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
        waitForPort(MIXED_PORT, log)
        waitForPort(CONTROLLER_PORT, log)
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

    private fun waitForPort(port: Int, log: File) {
        val deadline = System.currentTimeMillis() + STARTUP_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val current = process
            if (current == null || !current.isAlive) {
                throw IllegalStateException("Mihomo 进程已退出。${logTail(log)}")
            }
            if (canConnect(port)) {
                return
            }
            Thread.sleep(PORT_RETRY_DELAY_MS)
        }
        throw IllegalStateException("Mihomo 本地端口 $port 未就绪。最近日志：${logTail(log)}")
    }

    private fun canConnect(port: Int): Boolean {
        return runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", port), PORT_CONNECT_TIMEOUT_MS)
            }
        }.isSuccess
    }

    private fun logTail(log: File): String {
        if (!log.exists() || log.length() == 0L) {
            return "暂无 Mihomo 日志。"
        }
        return log.readLines(Charsets.UTF_8)
            .takeLast(LOG_TAIL_LINES)
            .joinToString(" ")
            .take(LOG_TAIL_CHARS)
            .trim()
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
        private const val MIXED_PORT = 17890
        private const val CONTROLLER_PORT = 17891
        private const val STARTUP_TIMEOUT_MS = 30_000L
        private const val PORT_RETRY_DELAY_MS = 200L
        private const val PORT_CONNECT_TIMEOUT_MS = 200
        private const val LOG_TAIL_LINES = 6
        private const val LOG_TAIL_CHARS = 500
        private const val MIHOMO_ANDROID_ARM64_SHA256 =
            "fe85504f9a8d9f4e92759de5634fe513b18cce0f259fe627e1a3fa56d886ecfa"
    }
}
