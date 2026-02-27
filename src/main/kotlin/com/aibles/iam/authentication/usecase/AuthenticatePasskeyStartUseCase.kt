package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class AuthenticatePasskeyStartUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val props: WebAuthnProperties,
) {
    data class Result(
        val sessionId: String,
        val rpId: String,
        val challenge: String,  // base64url
        val timeout: Int = 60_000,
        val userVerification: String = "preferred",
    )

    fun execute(): Result {
        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        redisChallengeStore.storeChallenge(sessionId, challengeBytes)
        return Result(
            sessionId = sessionId,
            rpId = props.rpId,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }
}
