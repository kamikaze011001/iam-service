package com.aibles.iam.shared.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.Jwt

class JwtRolesConverterTest {

    private val converter = SecurityConfig.buildRolesConverter()

    @Test
    fun `converts roles claim to ROLE_ prefixed authorities`() {
        val jwt = Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("user-1")
            .claim("roles", listOf("USER", "ADMIN"))
            .build()
        val authorities = converter.convert(jwt)
        assertThat(authorities!!.map { it.authority })
            .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN")
    }

    @Test
    fun `returns empty list when roles claim is absent`() {
        val jwt = Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("user-1")
            .build()
        val authorities = converter.convert(jwt)
        assertThat(authorities).isEmpty()
    }
}
