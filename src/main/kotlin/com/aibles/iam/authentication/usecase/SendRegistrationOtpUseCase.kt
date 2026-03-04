package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.security.SecureRandom

@Component
class SendRegistrationOtpUseCase(
    private val userRepository: UserRepository,
    private val otpStore: RedisOtpStore,
    private val emailService: EmailService,
) {
    companion object {
        private val random = SecureRandom()
    }

    data class Command(val email: String)

    fun execute(command: Command) {
        val email = command.email.lowercase().trim()

        if (userRepository.existsByEmail(email)) {
            throw ConflictException("Email already registered.", ErrorCode.EMAIL_ALREADY_REGISTERED)
        }

        val sends = otpStore.incrementSendCount(OtpScope.SIGNUP, email)
        if (sends > otpStore.maxSendCount) {
            throw BadRequestException("Too many OTP requests. Please try again later.", ErrorCode.OTP_SEND_LIMIT_EXCEEDED)
        }

        val code = String.format("%06d", random.nextInt(1_000_000))
        otpStore.saveOtp(OtpScope.SIGNUP, email, code)
        emailService.sendOtp(email, code)
    }
}
