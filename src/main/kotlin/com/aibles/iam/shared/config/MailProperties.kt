package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "mail")
data class MailProperties(
    val from: String = "noreply@yourdomain.com",
    val fromName: String = "IAM Service",
)
