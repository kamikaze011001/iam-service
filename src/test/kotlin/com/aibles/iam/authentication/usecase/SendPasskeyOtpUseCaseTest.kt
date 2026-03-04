package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.GetUserUseCase
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
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
        every { otpStore.saveOtp(OtpScope.PASSKEY_REG, userId.toString(), capture(codeSlot)) } returns Unit

        useCase.execute(SendPasskeyOtpUseCase.Command(userId))

        val code = codeSlot.captured
        assertThat(code).matches("\\d{6}")
        verify(exactly = 1) { emailService.sendOtp("user@test.com", code) }
    }

    @Test
    fun `throws BAD_REQUEST when user email is blank`() {
        val userId = UUID.randomUUID()
        val user = mockk<User> { every { email } returns "" }
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user

        assertThatThrownBy { useCase.execute(SendPasskeyOtpUseCase.Command(userId)) }
            .isInstanceOf(BadRequestException::class.java)
            .extracting("errorCode")
            .isEqualTo(ErrorCode.BAD_REQUEST)

        verify(exactly = 0) { otpStore.incrementSendCount(any(), any()) }
        verify(exactly = 0) { emailService.sendOtp(any(), any()) }
    }

    @Test
    fun `throws OTP_SEND_LIMIT_EXCEEDED when send count exceeds limit`() {
        val userId = UUID.randomUUID()
        val user = mockk<User> { every { email } returns "user@test.com" }
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user
        every { otpStore.incrementSendCount(OtpScope.PASSKEY_REG, userId.toString()) } returns RedisOtpStore.MAX_SEND_COUNT + 1
        every { otpStore.maxSendCount } returns RedisOtpStore.MAX_SEND_COUNT

        assertThatThrownBy { useCase.execute(SendPasskeyOtpUseCase.Command(userId)) }
            .isInstanceOf(BadRequestException::class.java)
            .extracting("errorCode")
            .isEqualTo(ErrorCode.OTP_SEND_LIMIT_EXCEEDED)

        verify(exactly = 0) { otpStore.saveOtp(any(), any(), any()) }
        verify(exactly = 0) { emailService.sendOtp(any(), any()) }
    }
}
