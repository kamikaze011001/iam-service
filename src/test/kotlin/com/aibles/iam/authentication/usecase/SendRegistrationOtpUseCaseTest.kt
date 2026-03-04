package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class SendRegistrationOtpUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val otpStore       = mockk<RedisOtpStore>(relaxed = true)
    private val emailService   = mockk<EmailService>(relaxed = true)
    private val useCase = SendRegistrationOtpUseCase(userRepository, otpStore, emailService)

    @Test
    fun `sends OTP to new email`() {
        every { userRepository.existsByEmail("new@test.com") } returns false

        val codeSlot = slot<String>()
        every { otpStore.saveOtp(OtpScope.SIGNUP, "new@test.com", capture(codeSlot)) } returns Unit

        useCase.execute(SendRegistrationOtpUseCase.Command("new@test.com"))

        assertThat(codeSlot.captured).matches("\\d{6}")
        verify(exactly = 1) { emailService.sendOtp("new@test.com", codeSlot.captured) }
    }

    @Test
    fun `throws EMAIL_ALREADY_REGISTERED when email exists`() {
        every { userRepository.existsByEmail("existing@test.com") } returns true

        assertThatThrownBy { useCase.execute(SendRegistrationOtpUseCase.Command("existing@test.com")) }
            .isInstanceOf(ConflictException::class.java)
            .extracting("errorCode")
            .isEqualTo(ErrorCode.EMAIL_ALREADY_REGISTERED)

        verify(exactly = 0) { otpStore.saveOtp(any(), any(), any()) }
        verify(exactly = 0) { emailService.sendOtp(any(), any()) }
    }

    @Test
    fun `throws OTP_SEND_LIMIT_EXCEEDED when rate limited`() {
        every { userRepository.existsByEmail("new@test.com") } returns false
        every { otpStore.incrementSendCount(OtpScope.SIGNUP, "new@test.com") } returns RedisOtpStore.MAX_SEND_COUNT + 1
        every { otpStore.maxSendCount } returns RedisOtpStore.MAX_SEND_COUNT

        assertThatThrownBy { useCase.execute(SendRegistrationOtpUseCase.Command("new@test.com")) }
            .isInstanceOf(BadRequestException::class.java)
            .extracting("errorCode")
            .isEqualTo(ErrorCode.OTP_SEND_LIMIT_EXCEEDED)

        verify(exactly = 0) { otpStore.saveOtp(any(), any(), any()) }
    }
}
