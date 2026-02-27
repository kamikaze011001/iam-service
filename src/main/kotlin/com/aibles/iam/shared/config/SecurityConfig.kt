package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val jwtProperties: JwtProperties,
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers(
                        "/oauth2/**", "/login/**",
                        "/api/v1/auth/refresh",
                        "/api/v1/auth/logout",
                        "/api/v1/auth/passkey/authenticate/start",
                        "/api/v1/auth/passkey/authenticate/finish",
                        "/actuator/**",
                        "/swagger-ui/**", "/v3/api-docs/**",
                    ).permitAll()
                    .anyRequest().authenticated()
            }
            .oauth2Login { it.successHandler(googleOAuth2SuccessHandler) }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(jwtDecoder()) } }
        return http.build()
    }

    @Bean
    fun jwtDecoder(): NimbusJwtDecoder {
        if (jwtProperties.publicKey.isBlank()) {
            // Fallback for test environments where JWT_PUBLIC_KEY is not configured
            return NimbusJwtDecoder.withPublicKey(generateTestKey()).build()
        }
        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(jwtProperties.publicKey))) as RSAPublicKey
        return NimbusJwtDecoder.withPublicKey(publicKey).build()
    }

    private fun generateTestKey(): RSAPublicKey {
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair().public as RSAPublicKey
    }
}
