package com.aibles.iam.authorization.infra

import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyPairGenerator
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.UUID

class JwtServiceTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }.generateKeyPair()

    private val props = JwtProperties(
        privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded),
        publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded),
        accessTokenTtlMinutes = 15,
    )
    private val service = JwtService(props)

    @Test
    fun `generated token contains correct claims`() {
        val userId = UUID.randomUUID()
        val token = service.generateAccessToken(userId, "a@b.com", setOf("USER"))
        val decoded = service.validate(token)
        assertThat(decoded.subject).isEqualTo(userId.toString())
        assertThat(decoded.getClaimAsString("email")).isEqualTo("a@b.com")
    }

    @Test
    fun `tampered token is rejected with UnauthorizedException`() {
        val token = service.generateAccessToken(UUID.randomUUID(), "a@b.com", setOf("USER"))
        val tampered = token.dropLast(5) + "XXXXX"
        val ex = assertThrows<UnauthorizedException> { service.validate(tampered) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
    }

    @Test
    fun `expired token is rejected with UnauthorizedException`() {
        // Build a token that expired 10 minutes ago directly via Nimbus to bypass encoder validation
        val past = Instant.now().minusSeconds(600)
        val claims = JWTClaimsSet.Builder()
            .subject(UUID.randomUUID().toString())
            .claim("email", "a@b.com")
            .issueTime(Date.from(past.minusSeconds(60)))
            .expirationTime(Date.from(past))
            .build()
        val header = JWSHeader(JWSAlgorithm.RS256)
        val signedJWT = SignedJWT(header, claims)
        signedJWT.sign(RSASSASigner(keyPair.private))
        val expiredToken = signedJWT.serialize()

        val ex = assertThrows<UnauthorizedException> { service.validate(expiredToken) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.TOKEN_EXPIRED)
    }
}
