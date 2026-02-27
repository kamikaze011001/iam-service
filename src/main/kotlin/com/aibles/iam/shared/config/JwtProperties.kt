package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("jwt")
data class JwtProperties(
    val privateKey: String = "",   // Base64-encoded PKCS#8 DER
    val publicKey: String = "",    // Base64-encoded X.509 DER
    val accessTokenTtlMinutes: Long = 15,
)
