package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.GetUserUseCase
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class SendPasskeyOtpUseCaseTest {

    private val getUserUseCase = mockk<GetUserUseCase>()
    private val otpStore       = mockk<RedisOtpStore>(relaxed = true)
    private val emailService   = mockk<EmailService>(relaxed = true)
    private val useCase = SendPasskeyOtpUseCase(getUserUseCase, otpStore, emailService)

    @Test
    fun `sends OTP to the user email and stores it`() {
        val userId = UUID.randomUUID()
        val user   = mockk<User> { every { email } returns "user@test.com" }
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user

        val codeSlot = slot<String>()
        every { otpStore.saveOtp(userId, capture(codeSlot)) } returns Unit

        useCase.execute(SendPasskeyOtpUseCase.Command(userId))

        val code = codeSlot.captured
        assertThat(code).matches("\\d{6}")
        verify(exactly = 1) { emailService.sendOtp("user@test.com", code) }
    }
}
