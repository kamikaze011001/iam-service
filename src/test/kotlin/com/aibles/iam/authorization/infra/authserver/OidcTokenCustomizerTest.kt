package com.aibles.iam.authorization.infra.authserver

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext

class OidcTokenCustomizerTest {

    private val userRepository = mockk<UserRepository>()
    private val customizer = OidcTokenCustomizer(userRepository)

    private val googleSub = "google-sub-123"
    private val testUser = User.create("user@example.com", "Test User", googleSub = googleSub)

    private fun buildContext(tokenTypeName: String, principalName: String): JwtEncodingContext {
        val authentication = mockk<Authentication>()
        every { authentication.name } returns principalName

        val claimsBuilder = mockk<JwtClaimsSet.Builder>(relaxed = true)
        every { claimsBuilder.claim(any(), any<Any>()) } returns claimsBuilder

        return mockk<JwtEncodingContext> {
            every { tokenType } returns OAuth2TokenType(tokenTypeName)
            every { getPrincipal<Authentication>() } returns authentication
            every { claims } returns claimsBuilder
        }
    }

    @Test
    fun `customize enriches ID token with email, name, and roles`() {
        every { userRepository.findByGoogleSub(googleSub) } returns testUser
        val ctx = buildContext(OidcParameterNames.ID_TOKEN, googleSub)

        customizer.customize(ctx)

        val claimsBuilder = ctx.claims
        verify { claimsBuilder.claim("email", testUser.email) }
        verify { claimsBuilder.claim("name", testUser.displayName ?: testUser.email) }
        verify { claimsBuilder.claim("roles", testUser.roles.toList()) }
    }

    @Test
    fun `customize does nothing for access tokens`() {
        val ctx = buildContext(OAuth2TokenType.ACCESS_TOKEN.value, googleSub)

        customizer.customize(ctx)

        verify(exactly = 0) { userRepository.findByGoogleSub(any()) }
    }

    @Test
    fun `customize does nothing when user not found`() {
        every { userRepository.findByGoogleSub(googleSub) } returns null
        val ctx = buildContext(OidcParameterNames.ID_TOKEN, googleSub)

        customizer.customize(ctx)  // must not throw
        verify(exactly = 0) { ctx.claims.claim(any(), any<Any>()) }
    }
}
