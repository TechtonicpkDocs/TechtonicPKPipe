package org.schabi.newpipe

import java.net.InetAddress
import java.net.UnknownHostException
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.dnsoverhttps.DnsOverHttps

/**
 * TechTonicPipe's VPN-proof DNS.
 *
 * Why this exists: some VPNs ship a broken or filtered DNS. The system default DNS
 * then fails to resolve hosts and the whole app looks "blocked by the VPN", even
 * though the network itself is fine. Encrypted DNS-over-HTTPS bypasses the VPN's
 * DNS entirely (the same trick Chrome's "Secure DNS" uses — which is why Chrome
 * keeps working where the stock app fails).
 *
 * Strategy: Cloudflare DoH -> Google DoH -> system DNS. First one that answers wins,
 * so the app keeps working on any VPN and any network.
 */
object TechTonicDns {

    fun create(): Dns {
        // Plain client used only for the encrypted DNS queries themselves.
        val bootstrap = OkHttpClient()
        val dohProviders = listOf(
            doh(bootstrap, "https://1.1.1.1/dns-query", "1.1.1.1", "1.0.0.1"),
            doh(bootstrap, "https://8.8.8.8/dns-query", "8.8.8.8", "8.8.4.4")
        )
        return FallbackDns(dohProviders + Dns.SYSTEM)
    }

    private fun doh(
        client: OkHttpClient,
        url: String,
        vararg bootstrapIps: String
    ): Dns {
        return DnsOverHttps.Builder()
            .client(client)
            // Bootstrap IPs: the DoH server is reached by IP, so no DNS is needed
            // to ask DNS. This breaks the chicken-and-egg loop on broken VPN DNS.
            .bootstrapDnsHosts(bootstrapIps.map { InetAddress.getByName(it) })
            .url(url.toHttpUrl())
            .build()
    }

    private class FallbackDns(private val chain: List<Dns>) : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            var lastError: Exception? = null
            for (dns in chain) {
                try {
                    return dns.lookup(hostname)
                } catch (e: Exception) {
                    lastError = e
                }
            }
            throw lastError ?: UnknownHostException(hostname)
        }
    }
}
