package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class VerifyPasskeyOtpUseCaseTest {

    private val otpStore = mockk<RedisOtpStore>(relaxed = true)
    private val useCase  = VerifyPasskeyOtpUseCase(otpStore)

    @Test
    fun `returns otpToken on correct code`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns "123456"
        every { otpStore.incrementAttempts(userId) } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val result = useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))

        assertThat(result.otpToken).isNotBlank()
        verify { otpStore.deleteOtp(userId) }
        verify { otpStore.saveOtpToken(result.otpToken, userId) }
    }

    @Test
    fun `throws OTP_INVALID on wrong code`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns "999999"
        every { otpStore.incrementAttempts(userId) } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_INVALID)
    }

    @Test
    fun `throws OTP_EXPIRED when no OTP in store`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns null
        every { otpStore.incrementAttempts(userId) } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }

    @Test
    fun `throws OTP_MAX_ATTEMPTS when attempts exceeded`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns "123456"
        every { otpStore.incrementAttempts(userId) } returns 4L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_MAX_ATTEMPTS)
    }
}
