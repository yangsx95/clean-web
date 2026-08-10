package app.cleanweb.mobile

object CleanWebMihomoLauncher {
  init {
    System.loadLibrary("cleanweb_mobile_lib")
  }

  external fun spawnMihomo(
    executable: String,
    runtimeDir: String,
    configPath: String,
    tunFd: Int,
  ): Int

  external fun waitMihomo(pid: Int): Int

  external fun terminateMihomo(pid: Int)
}
