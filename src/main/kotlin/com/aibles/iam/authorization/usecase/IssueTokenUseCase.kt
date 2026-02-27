package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.authorization.infra.JwtService
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.config.JwtProperties
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.UUID

@Component
class IssueTokenUseCase(
    private val jwtService: JwtService,
    private val tokenStore: TokenStore,
    private val props: JwtProperties,
) {
    data class Command(val user: User)
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val accessToken = jwtService.generateAccessToken(
            command.user.id, command.user.email, command.user.roles
        )
        val refreshToken = UUID.randomUUID().toString()
        tokenStore.storeRefreshToken(refreshToken, command.user.id, Duration.ofDays(30))
        return Result(accessToken, refreshToken, props.accessTokenTtlMinutes * 60)
    }
}
