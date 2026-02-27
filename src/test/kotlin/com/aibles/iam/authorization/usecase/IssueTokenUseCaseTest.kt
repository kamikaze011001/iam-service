package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.authorization.infra.JwtService
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.config.JwtProperties
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.util.Base64

class IssueTokenUseCaseTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val props = JwtProperties(
        privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded),
        publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded),
        accessTokenTtlMinutes = 15,
    )
    private val jwtService = JwtService(props)
    private val tokenStore = mockk<TokenStore>()
    private val useCase = IssueTokenUseCase(jwtService, tokenStore, props)

    @Test
    fun `issues access and refresh tokens for user`() {
        val user = User.create("a@b.com")
        justRun { tokenStore.storeRefreshToken(any(), user.id, any()) }

        val result = useCase.execute(IssueTokenUseCase.Command(user))

        assertThat(result.accessToken).isNotBlank()
        assertThat(result.refreshToken).isNotBlank()
        assertThat(result.expiresIn).isEqualTo(15L * 60)
        verify(exactly = 1) { tokenStore.storeRefreshToken(result.refreshToken, user.id, any()) }
    }

    @Test
    fun `access token contains correct sub and email claims`() {
        val user = User.create("b@example.com")
        justRun { tokenStore.storeRefreshToken(any(), any(), any()) }

        val result = useCase.execute(IssueTokenUseCase.Command(user))
        val decoded = jwtService.validate(result.accessToken)

        assertThat(decoded.subject).isEqualTo(user.id.toString())
        assertThat(decoded.getClaimAsString("email")).isEqualTo("b@example.com")
    }
}
