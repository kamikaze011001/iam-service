package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.usecase.GetUserUseCase
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.UUID

@Component
class SendPasskeyOtpUseCase(
    private val getUserUseCase: GetUserUseCase,
    private val otpStore: RedisOtpStore,
    private val emailService: EmailService,
) {
    data class Command(val userId: UUID)

    fun execute(command: Command) {
        val user = getUserUseCase.execute(GetUserUseCase.Query(command.userId))
        val code = String.format("%06d", SecureRandom().nextInt(1_000_000))
        otpStore.saveOtp(command.userId, code)
        emailService.sendOtp(user.email, code)
    }
}
