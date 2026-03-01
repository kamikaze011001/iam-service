package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "cors")
data class CorsProperties(
    val allowedOrigins: List<String> = listOf("http://localhost:3000"),
    val allowedMethods: List<String> = listOf("GET", "POST", "PATCH", "DELETE", "OPTIONS"),
    val allowedHeaders: List<String> = listOf("Authorization", "Content-Type"),
    val maxAge: Long = 3600,
)
