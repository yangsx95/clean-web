package app.cleanweb.mobile

object CleanWebDnsEngine {
  init {
    System.loadLibrary("cleanweb_mobile_lib")
  }

  external fun updatePolicy(policyJson: String): String?

  external fun handleDnsQuery(query: ByteArray): ByteArray?
}
