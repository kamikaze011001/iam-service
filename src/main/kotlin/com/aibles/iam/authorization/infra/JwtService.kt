package com.aibles.iam.authorization.infra

import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.jwt.JwtValidationException
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.stereotype.Component
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

@Component
class JwtService(private val rsaKey: RSAKey, private val props: JwtProperties) {

    private val encoder: NimbusJwtEncoder
    private val decoder: NimbusJwtDecoder

    init {
        encoder = NimbusJwtEncoder(ImmutableJWKSet(JWKSet(rsaKey)))
        decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build()
    }

    fun generateAccessToken(userId: UUID, email: String, roles: Set<String>): String {
        val now = Instant.now()
        val expiry = now.plus(props.accessTokenTtlMinutes, ChronoUnit.MINUTES)
        val claims = JwtClaimsSet.builder()
            .subject(userId.toString())
            .claim("email", email)
            .claim("roles", roles.toList())
            .issuedAt(now)
            .expiresAt(expiry)
            .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).build()
        return encoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }

    fun validate(token: String): Jwt {
        try {
            return decoder.decode(token)
        } catch (e: JwtValidationException) {
            val code = if (e.errors.any { it.description.contains("expired", ignoreCase = true) })
                ErrorCode.TOKEN_EXPIRED else ErrorCode.TOKEN_INVALID
            throw UnauthorizedException(e.message ?: "Invalid token", code)
        } catch (e: JwtException) {
            throw UnauthorizedException(e.message ?: "Invalid token", ErrorCode.TOKEN_INVALID)
        }
    }
}
