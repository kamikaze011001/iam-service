package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class StartRegistrationUseCase(
    private val otpStore: RedisOtpStore,
    private val ceremonyService: WebAuthnCeremonyService,
    private val challengeStore: RedisChallengeStore,
) {
    data class Command(val otpToken: String, val displayName: String?)
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val email: String,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>>,
        val timeout: Int,
        val attestation: String,
    )

    fun execute(command: Command): Result {
        val email = otpStore.consumeOtpToken(OtpScope.SIGNUP, command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)

        val challengeData = ceremonyService.createChallenge()

        // Store email alongside challenge session so finish step can retrieve it
        challengeStore.storeSessionData(challengeData.sessionId, "email", email)

        return Result(
            sessionId = challengeData.sessionId,
            rpId = challengeData.rpId,
            rpName = challengeData.rpName,
            email = email,
            challenge = challengeData.challenge,
            pubKeyCredParams = challengeData.pubKeyCredParams,
            timeout = challengeData.timeout,
            attestation = challengeData.attestation,
        )
    }
}
