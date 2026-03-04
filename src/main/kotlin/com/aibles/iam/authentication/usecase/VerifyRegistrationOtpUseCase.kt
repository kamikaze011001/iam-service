package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class VerifyRegistrationOtpUseCase(private val otpStore: RedisOtpStore) {

    data class Command(val email: String, val code: String)
    data class Result(val otpToken: String)

    fun execute(command: Command): Result {
        val email = command.email.lowercase().trim()
        val attempts = otpStore.incrementAttempts(OtpScope.SIGNUP, email)
        if (attempts > otpStore.maxAttempts) {
            throw BadRequestException("Too many OTP attempts. Please request a new code.", ErrorCode.OTP_MAX_ATTEMPTS)
        }

        val stored = otpStore.getOtp(OtpScope.SIGNUP, email)
            ?: throw BadRequestException("OTP expired. Please request a new code.", ErrorCode.OTP_EXPIRED)

        if (stored != command.code) {
            throw BadRequestException("Invalid OTP code.", ErrorCode.OTP_INVALID)
        }

        val otpToken = UUID.randomUUID().toString()
        otpStore.deleteOtp(OtpScope.SIGNUP, email)
        otpStore.saveOtpToken(OtpScope.SIGNUP, otpToken, email)
        return Result(otpToken)
    }
}
