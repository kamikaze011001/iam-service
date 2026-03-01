package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler
import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val googleOAuth2FailureHandler: GoogleOAuth2FailureHandler,
    private val jwtDecoder: JwtDecoder,
) {

    @Bean
    @Order(2)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
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
}
