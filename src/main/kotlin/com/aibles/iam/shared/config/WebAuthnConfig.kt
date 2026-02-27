package com.aibles.iam.shared.config

import com.webauthn4j.WebAuthnManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class WebAuthnConfig {
    @Bean
    fun webAuthnManager(): WebAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()
}
