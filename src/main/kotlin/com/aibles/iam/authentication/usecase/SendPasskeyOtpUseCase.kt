package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.UUID

@Component
class SendPasskeyOtpUseCase(
    private val getUserUseCase: GetUserUseCase,
    private val otpStore: RedisOtpStore,
    private val emailService: EmailService,
) {
    companion object {
        private val random = SecureRandom()
    }

    data class Command(val userId: UUID)

    fun execute(command: Command) {
        val user = getUserUseCase.execute(GetUserUseCase.Query(command.userId))

        if (user.email.isBlank()) {
            throw BadRequestException("User has no verified email address.", ErrorCode.BAD_REQUEST)
        }

        val sends = otpStore.incrementSendCount(command.userId)
        if (sends > otpStore.maxSendCount) {
            throw BadRequestException("Too many OTP requests. Please try again later.", ErrorCode.OTP_SEND_LIMIT_EXCEEDED)
        }

        val code = String.format("%06d", random.nextInt(1_000_000))
        otpStore.saveOtp(command.userId, code)
        emailService.sendOtp(user.email, code)
    }
}
