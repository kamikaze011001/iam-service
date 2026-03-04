package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class VerifyRegistrationOtpUseCaseTest {

    private val otpStore = mockk<RedisOtpStore>(relaxed = true)
    private val useCase  = VerifyRegistrationOtpUseCase(otpStore)

    @Test
    fun `returns otpToken on correct code`() {
        every { otpStore.getOtp(OtpScope.SIGNUP, "user@test.com") } returns "123456"
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val result = useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))

        assertThat(result.otpToken).isNotBlank()
        verify { otpStore.deleteOtp(OtpScope.SIGNUP, "user@test.com") }
        verify { otpStore.saveOtpToken(OtpScope.SIGNUP, result.otpToken, "user@test.com") }
    }

    @Test
    fun `throws OTP_INVALID on wrong code`() {
        every { otpStore.getOtp(OtpScope.SIGNUP, "user@test.com") } returns "999999"
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_INVALID)
    }

    @Test
    fun `throws OTP_EXPIRED when no OTP in store`() {
        every { otpStore.getOtp(OtpScope.SIGNUP, "user@test.com") } returns null
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }

    @Test
    fun `throws OTP_MAX_ATTEMPTS when attempts exceeded`() {
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 4L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_MAX_ATTEMPTS)
    }
}
