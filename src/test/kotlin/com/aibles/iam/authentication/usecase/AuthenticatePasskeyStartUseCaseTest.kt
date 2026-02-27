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

class AuthenticatePasskeyStartUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test")
    private val useCase = AuthenticatePasskeyStartUseCase(redisChallengeStore, props)

    @Test
    fun `execute returns sessionId, rpId, and 32-byte challenge`() {
        val challengeSlot = slot<ByteArray>()
        every { redisChallengeStore.storeChallenge(any(), capture(challengeSlot)) } just runs

        val result = useCase.execute()

        assertThat(result.sessionId).isNotBlank()
        assertThat(result.rpId).isEqualTo("localhost")
        assertThat(result.challenge).isNotBlank()
        assertThat(challengeSlot.captured).hasSize(32)
    }
}
