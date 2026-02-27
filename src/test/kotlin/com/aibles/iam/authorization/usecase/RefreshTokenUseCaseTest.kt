package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.authorization.infra.JwtService
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import com.aibles.iam.shared.error.UnauthorizedException
import com.nimbusds.jose.jwk.RSAKey
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class RefreshTokenUseCaseTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
        .privateKey(keyPair.private as RSAPrivateKey)
        .keyID("test-rsa")
        .build()
    private val props = JwtProperties(
        privateKey = "",
        publicKey = "",
        accessTokenTtlMinutes = 15,
    )
    private val tokenStore = mockk<TokenStore>()
    private val getUserUseCase = mockk<GetUserUseCase>()
    private val jwtService = JwtService(rsaKey, props)
    private val issueToken = IssueTokenUseCase(jwtService, tokenStore, props)
    private val useCase = RefreshTokenUseCase(tokenStore, getUserUseCase, issueToken)

    @Test
    fun `valid refresh token returns new token pair`() {
        val user = User.create("a@b.com")
        every { tokenStore.validateAndConsume("rt-valid") } returns user.id
        every { getUserUseCase.execute(GetUserUseCase.Query(user.id)) } returns user
        justRun { tokenStore.storeRefreshToken(any(), user.id, any()) }

        val result = useCase.execute(RefreshTokenUseCase.Command("rt-valid"))

        assertThat(result.accessToken).isNotBlank()
        assertThat(result.refreshToken).isNotBlank()
    }

    @Test
    fun `disabled user throws ForbiddenException with USER_DISABLED`() {
        val user = User.create("a@b.com").also { it.disable() }
        every { tokenStore.validateAndConsume("rt-disabled") } returns user.id
        every { getUserUseCase.execute(GetUserUseCase.Query(user.id)) } returns user

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(RefreshTokenUseCase.Command("rt-disabled"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
    }

    @Test
    fun `invalid refresh token propagates UnauthorizedException with TOKEN_INVALID`() {
        every { tokenStore.validateAndConsume("bad-token") } throws
            UnauthorizedException("expired", ErrorCode.TOKEN_INVALID)

        val ex = assertThrows<UnauthorizedException> {
            useCase.execute(RefreshTokenUseCase.Command("bad-token"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
    }
}
