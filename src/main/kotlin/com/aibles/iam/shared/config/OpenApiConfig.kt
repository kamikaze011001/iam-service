package com.aibles.iam.shared.config

import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Contact
import io.swagger.v3.oas.models.info.Info
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {

    @Bean
    fun openAPI(): OpenAPI = OpenAPI().info(
        Info()
            .title("IAM Service API")
            .description("Identity & Access Management — Google OAuth2, Passkey/WebAuthn, OAuth2/OIDC SSO, Audit Logging")
            .version("1.0.0")
            .contact(Contact().name("Aibles").url("https://aibles.com"))
    )
}
