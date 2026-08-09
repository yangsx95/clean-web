package app.cleanweb.mobile

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

object CleanWebTunDns {
  private const val IPV4_HEADER_MIN_LENGTH = 20
  private const val UDP_HEADER_LENGTH = 8
  private const val UDP_PROTOCOL = 17
  private const val DNS_PORT = 53

  data class Query(
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
  )

  fun parseQuery(packet: ByteArray, length: Int): Query? {
    if (length < IPV4_HEADER_MIN_LENGTH + UDP_HEADER_LENGTH) return null
    val version = (packet[0].toInt() ushr 4) and 0x0f
    if (version != 4) return null
    val headerLength = (packet[0].toInt() and 0x0f) * 4
    if (headerLength < IPV4_HEADER_MIN_LENGTH || length < headerLength + UDP_HEADER_LENGTH) return null
    if ((packet[9].toInt() and 0xff) != UDP_PROTOCOL) return null
    val totalLength = readU16(packet, 2).coerceAtMost(length)
    val udpOffset = headerLength
    val destinationPort = readU16(packet, udpOffset + 2)
    if (destinationPort != DNS_PORT) return null
    val udpLength = readU16(packet, udpOffset + 4)
    if (udpLength < UDP_HEADER_LENGTH || udpOffset + udpLength > totalLength) return null
    val payloadOffset = udpOffset + UDP_HEADER_LENGTH
    val payloadLength = udpLength - UDP_HEADER_LENGTH
    return Query(
      sourceAddress = packet.copyOfRange(12, 16),
      destinationAddress = packet.copyOfRange(16, 20),
      sourcePort = readU16(packet, udpOffset),
      destinationPort = destinationPort,
      payload = packet.copyOfRange(payloadOffset, payloadOffset + payloadLength),
    )
  }

  fun buildResponse(query: Query, dnsPayload: ByteArray): ByteArray {
    val totalLength = IPV4_HEADER_MIN_LENGTH + UDP_HEADER_LENGTH + dnsPayload.size
    val packet = ByteArray(totalLength)
    packet[0] = 0x45
    packet[1] = 0
    writeU16(packet, 2, totalLength)
    writeU16(packet, 4, 0)
    writeU16(packet, 6, 0)
    packet[8] = 64
    packet[9] = UDP_PROTOCOL.toByte()
    query.destinationAddress.copyInto(packet, 12)
    query.sourceAddress.copyInto(packet, 16)
    writeU16(packet, 10, ipv4Checksum(packet, 0, IPV4_HEADER_MIN_LENGTH))

    val udpOffset = IPV4_HEADER_MIN_LENGTH
    writeU16(packet, udpOffset, query.destinationPort)
    writeU16(packet, udpOffset + 2, query.sourcePort)
    writeU16(packet, udpOffset + 4, UDP_HEADER_LENGTH + dnsPayload.size)
    writeU16(packet, udpOffset + 6, 0)
    dnsPayload.copyInto(packet, udpOffset + UDP_HEADER_LENGTH)
    return packet
  }

  fun forwardDns(
    query: Query,
    upstreams: List<InetAddress>,
    protectSocket: (DatagramSocket) -> Boolean,
  ): ByteArray? {
    for (upstream in upstreams) {
      try {
        DatagramSocket().use { socket ->
          if (!protectSocket(socket)) return null
          socket.soTimeout = 1200
          socket.connect(upstream, DNS_PORT)
          socket.send(DatagramPacket(query.payload, query.payload.size))
          val buffer = ByteArray(4096)
          val response = DatagramPacket(buffer, buffer.size)
          socket.receive(response)
          if (response.length >= 2 && sameTransaction(query.payload, buffer)) {
            return buffer.copyOf(response.length)
          }
        }
      } catch (_: Exception) {
        // Try the next resolver. The caller records one failure only if all fail.
      }
    }
    return null
  }

  fun isNxDomain(payload: ByteArray): Boolean {
    return payload.size >= 4 && (payload[3].toInt() and 0x0f) == 3
  }

  private fun sameTransaction(request: ByteArray, response: ByteArray): Boolean {
    return request.size >= 2 && response.size >= 2 &&
      request[0] == response[0] && request[1] == response[1]
  }

  private fun readU16(packet: ByteArray, offset: Int): Int {
    return ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
  }

  private fun writeU16(packet: ByteArray, offset: Int, value: Int) {
    packet[offset] = ((value ushr 8) and 0xff).toByte()
    packet[offset + 1] = (value and 0xff).toByte()
  }

  private fun ipv4Checksum(packet: ByteArray, offset: Int, length: Int): Int {
    var sum = 0
    var index = offset
    while (index < offset + length) {
      if (index != offset + 10) {
        sum += readU16(packet, index)
      }
      index += 2
    }
    while ((sum ushr 16) != 0) {
      sum = (sum and 0xffff) + (sum ushr 16)
    }
    return sum.inv() and 0xffff
  }
}
