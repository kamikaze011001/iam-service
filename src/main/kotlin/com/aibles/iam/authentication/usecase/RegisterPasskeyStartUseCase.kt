package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class RegisterPasskeyStartUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val props: WebAuthnProperties,
) {
    data class Command(val userId: UUID, val userEmail: String, val displayName: String?)
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val userId: String,        // UUID as string for identification
        val userEmail: String,
        val userDisplayName: String?,
        val challenge: String,     // base64url challenge
        val pubKeyCredParams: List<Map<String, Any>> = listOf(
            mapOf("type" to "public-key", "alg" to -7),    // ES256
            mapOf("type" to "public-key", "alg" to -257),  // RS256
        ),
        val timeout: Int = 60_000,
        val attestation: String = "none",
    )

    fun execute(command: Command): Result {
        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        redisChallengeStore.storeChallenge(sessionId, challengeBytes)

        return Result(
            sessionId = sessionId,
            rpId = props.rpId,
            rpName = props.rpName,
            userId = command.userId.toString(),
            userEmail = command.userEmail,
            userDisplayName = command.displayName,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }
}
