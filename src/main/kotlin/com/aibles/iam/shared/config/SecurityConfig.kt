package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler
import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import com.aibles.iam.shared.security.ApiAccessDeniedHandler
import com.aibles.iam.shared.security.ApiAuthEntryPoint
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.convert.converter.Converter
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // enables @PreAuthorize on use cases or controllers when needed
@EnableConfigurationProperties(CorsProperties::class)
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val googleOAuth2FailureHandler: GoogleOAuth2FailureHandler,
    private val jwtDecoder: JwtDecoder,
    private val corsProperties: CorsProperties,
    private val apiAuthEntryPoint: ApiAuthEntryPoint,
    private val apiAccessDeniedHandler: ApiAccessDeniedHandler,
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
                        "/api/v1/auth/register/**",
                        "/actuator/health", "/actuator/info",
                        "/swagger-ui/**", "/v3/api-docs/**",
                    ).permitAll()
                    .requestMatchers("/api/v1/users/**", "/api/v1/audit-logs/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
            }
            .oauth2Login {
                it.successHandler(googleOAuth2SuccessHandler)
                it.failureHandler(googleOAuth2FailureHandler)
            }
            .oauth2ResourceServer {
                it.jwt { jwt ->
                    jwt.decoder(jwtDecoder)
                    jwt.jwtAuthenticationConverter(
                        JwtAuthenticationConverter().apply {
                            setJwtGrantedAuthoritiesConverter(buildRolesConverter())
                        }
                    )
                }
            }
            .exceptionHandling {
                it.authenticationEntryPoint(apiAuthEntryPoint)
                it.accessDeniedHandler(apiAccessDeniedHandler)
            }
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

    companion object {
        fun buildRolesConverter(): Converter<Jwt, Collection<GrantedAuthority>> = Converter { jwt ->
            (jwt.getClaimAsStringList("roles") ?: emptyList())
                .map { SimpleGrantedAuthority("ROLE_$it") }
        }
    }
}
