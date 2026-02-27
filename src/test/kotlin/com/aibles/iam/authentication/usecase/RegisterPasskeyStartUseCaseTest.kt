package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class RegisterPasskeyStartUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test App")
    private val useCase = RegisterPasskeyStartUseCase(redisChallengeStore, props)

    @Test
    fun `execute returns sessionId and options with rpId and challenge`() {
        val challengeSlot = slot<ByteArray>()
        every { redisChallengeStore.storeChallenge(any(), capture(challengeSlot)) } just runs

        val userId = UUID.randomUUID()
        val result = useCase.execute(RegisterPasskeyStartUseCase.Command(userId, "user@test.com", "Test User"))

        assertThat(result.sessionId).isNotBlank()
        assertThat(result.rpId).isEqualTo("localhost")
        assertThat(result.challenge).isNotBlank()          // base64url-encoded challenge
        assertThat(result.userId).isEqualTo(userId.toString())
        assertThat(challengeSlot.captured).hasSize(32)     // 32 random bytes
    }
}
