package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class VerifyPasskeyOtpUseCase(private val otpStore: RedisOtpStore) {

    data class Command(val userId: UUID, val code: String)
    data class Result(val otpToken: String)

    fun execute(command: Command): Result {
        val key = command.userId.toString()
        val attempts = otpStore.incrementAttempts(OtpScope.PASSKEY_REG, key)
        if (attempts > otpStore.maxAttempts) {
            throw BadRequestException("Too many OTP attempts. Please request a new code.", ErrorCode.OTP_MAX_ATTEMPTS)
        }

        val stored = otpStore.getOtp(OtpScope.PASSKEY_REG, key)
            ?: throw BadRequestException("OTP expired. Please request a new code.", ErrorCode.OTP_EXPIRED)

        if (stored != command.code) {
            throw BadRequestException("Invalid OTP code.", ErrorCode.OTP_INVALID)
        }

        val otpToken = UUID.randomUUID().toString()
        otpStore.deleteOtp(OtpScope.PASSKEY_REG, key)
        otpStore.saveOtpToken(OtpScope.PASSKEY_REG, otpToken, key)
        return Result(otpToken)
    }
}
