package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class RegisterPasskeyStartUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val otpStore = mockk<RedisOtpStore>(relaxed = true)
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test App")
    private val useCase = RegisterPasskeyStartUseCase(redisChallengeStore, otpStore, props)

    @Test
    fun `execute returns sessionId and options with rpId and challenge`() {
        val userId = UUID.randomUUID()
        val otpToken = UUID.randomUUID().toString()
        every { otpStore.consumeOtpToken(OtpScope.PASSKEY_REG, otpToken) } returns userId.toString()

        val challengeSlot = slot<ByteArray>()
        every { redisChallengeStore.storeChallenge(any(), capture(challengeSlot)) } just runs

        val result = useCase.execute(
            RegisterPasskeyStartUseCase.Command(userId, "user@test.com", "Test User", otpToken)
        )

        assertThat(result.sessionId).isNotBlank()
        assertThat(result.rpId).isEqualTo("localhost")
        assertThat(result.challenge).isNotBlank()
        assertThat(result.userId).isEqualTo(userId.toString())
        assertThat(challengeSlot.captured).hasSize(32)
    }

    @Test
    fun `throws OTP_EXPIRED when otpToken is not found in store`() {
        every { otpStore.consumeOtpToken(OtpScope.PASSKEY_REG, "bad-token") } returns null

        val ex = assertThrows<BadRequestException> {
            useCase.execute(
                RegisterPasskeyStartUseCase.Command(
                    userId = UUID.randomUUID(),
                    userEmail = "u@test.com",
                    displayName = "Test",
                    otpToken = "bad-token",
                )
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }

    @Test
    fun `throws UNAUTHORIZED when otpToken belongs to a different user`() {
        val userId = UUID.randomUUID()
        val differentUserId = UUID.randomUUID()
        every { otpStore.consumeOtpToken(OtpScope.PASSKEY_REG, "valid-token") } returns differentUserId.toString()

        val ex = assertThrows<UnauthorizedException> {
            useCase.execute(
                RegisterPasskeyStartUseCase.Command(
                    userId = userId,
                    userEmail = "u@test.com",
                    displayName = "Test",
                    otpToken = "valid-token",
                )
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.UNAUTHORIZED)
    }
}
