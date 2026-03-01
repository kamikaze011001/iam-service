package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler
import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(CorsProperties::class)
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val googleOAuth2FailureHandler: GoogleOAuth2FailureHandler,
    private val jwtDecoder: JwtDecoder,
    private val corsProperties: CorsProperties,
) {

    @Bean
    @Order(2)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .cors { it.configurationSource(corsConfigurationSource()) }
            .csrf { it.disable() }
            .headers { headers ->
                headers.frameOptions { it.deny() }
            }
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
            .oauth2Login {
                it.successHandler(googleOAuth2SuccessHandler)
                it.failureHandler(googleOAuth2FailureHandler)
            }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(jwtDecoder) } }
        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val config = CorsConfiguration().apply {
            allowedOrigins = corsProperties.allowedOrigins
            allowedMethods = corsProperties.allowedMethods
            allowedHeaders = corsProperties.allowedHeaders
            maxAge = corsProperties.maxAge
        }
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return source
    }
}
