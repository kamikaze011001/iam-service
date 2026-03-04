package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class RegisterPasskeyStartUseCase(
    private val otpStore: RedisOtpStore,
    private val ceremonyService: WebAuthnCeremonyService,
) {
    data class Command(
        val userId: UUID,
        val userEmail: String,
        val displayName: String?,
        val otpToken: String,
    )
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val userId: String,
        val userEmail: String,
        val userDisplayName: String?,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>> = listOf(
            mapOf("type" to "public-key", "alg" to -7),
            mapOf("type" to "public-key", "alg" to -257),
        ),
        val timeout: Int = 60_000,
        val attestation: String = "none",
    )

    fun execute(command: Command): Result {
        val tokenOwner = otpStore.consumeOtpToken(OtpScope.PASSKEY_REG, command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)
        if (tokenOwner != command.userId.toString()) {
            throw UnauthorizedException("OTP token does not match the authenticated user.", ErrorCode.UNAUTHORIZED)
        }

        val challengeData = ceremonyService.createChallenge()
        return Result(
            sessionId = challengeData.sessionId,
            rpId = challengeData.rpId,
            rpName = challengeData.rpName,
            userId = command.userId.toString(),
            userEmail = command.userEmail,
            userDisplayName = command.displayName,
            challenge = challengeData.challenge,
        )
    }
}
