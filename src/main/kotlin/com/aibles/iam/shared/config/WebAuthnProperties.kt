package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("webauthn")
data class WebAuthnProperties(
    val rpId: String = "localhost",
    val rpOrigin: String = "http://localhost:8080",
    val rpName: String = "IAM Service",
)
