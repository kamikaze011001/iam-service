package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "rate-limit")
data class RateLimitProperties(
    val enabled: Boolean = true,
    val requestsPerMinute: Long = 100,
    val trustedProxies: List<String> = emptyList(),
)
