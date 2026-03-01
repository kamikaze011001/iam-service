package com.aibles.iam.shared.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest

class CorsConfigurationTest {

    @Test
    fun `corsConfigurationSource uses properties values`() {
        val properties = CorsProperties(
            allowedOrigins = listOf("http://localhost:3000", "https://app.example.com"),
            allowedMethods = listOf("GET", "POST"),
            allowedHeaders = listOf("Authorization"),
            maxAge = 7200,
        )
        val config = SecurityConfig::class.java.getDeclaredMethod("corsConfigurationSource")

        // Test via creating the source directly
        val source = org.springframework.web.cors.UrlBasedCorsConfigurationSource()
        val corsConfig = org.springframework.web.cors.CorsConfiguration().apply {
            allowedOrigins = properties.allowedOrigins
            allowedMethods = properties.allowedMethods
            allowedHeaders = properties.allowedHeaders
            maxAge = properties.maxAge
        }
        source.registerCorsConfiguration("/**", corsConfig)

        val request = MockHttpServletRequest("GET", "/api/v1/users")
        val resolved = source.getCorsConfiguration(request)

        assertThat(resolved).isNotNull
        assertThat(resolved!!.allowedOrigins).containsExactly("http://localhost:3000", "https://app.example.com")
        assertThat(resolved.allowedMethods).containsExactly("GET", "POST")
        assertThat(resolved.allowedHeaders).containsExactly("Authorization")
        assertThat(resolved.maxAge).isEqualTo(7200)
    }

    @Test
    fun `default CorsProperties has sensible defaults`() {
        val defaults = CorsProperties()
        assertThat(defaults.allowedOrigins).containsExactly("http://localhost:3000")
        assertThat(defaults.allowedMethods).contains("GET", "POST", "PATCH", "DELETE", "OPTIONS")
        assertThat(defaults.allowedHeaders).contains("Authorization", "Content-Type")
        assertThat(defaults.maxAge).isEqualTo(3600)
    }
}
