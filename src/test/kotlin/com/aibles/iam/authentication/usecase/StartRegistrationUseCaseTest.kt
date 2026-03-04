package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class StartRegistrationUseCaseTest {

    private val otpStore = mockk<RedisOtpStore>()
    private val ceremonyService = mockk<WebAuthnCeremonyService>()
    private val challengeStore = mockk<RedisChallengeStore>(relaxed = true)
    private val useCase = StartRegistrationUseCase(otpStore, ceremonyService, challengeStore)

    @Test
    fun `returns challenge data on valid otpToken`() {
        every { otpStore.consumeOtpToken(OtpScope.SIGNUP, "valid-token") } returns "user@test.com"
        every { ceremonyService.createChallenge() } returns WebAuthnCeremonyService.ChallengeData(
            sessionId = "session-1", rpId = "localhost", rpName = "IAM",
            challenge = "Y2hhbGxlbmdl",
        )

        val result = useCase.execute(StartRegistrationUseCase.Command("valid-token", "My Key"))

        assertThat(result.sessionId).isEqualTo("session-1")
        assertThat(result.email).isEqualTo("user@test.com")
        assertThat(result.challenge).isEqualTo("Y2hhbGxlbmdl")
        verify { challengeStore.storeSessionData("session-1", "email", "user@test.com") }
    }

    @Test
    fun `throws OTP_EXPIRED when otpToken is invalid`() {
        every { otpStore.consumeOtpToken(OtpScope.SIGNUP, "bad-token") } returns null

        val ex = assertThrows<BadRequestException> {
            useCase.execute(StartRegistrationUseCase.Command("bad-token", null))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }
}
