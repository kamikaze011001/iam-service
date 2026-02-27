package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class RegisterPasskeyFinishUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val credentialRepository = mockk<PasskeyCredentialRepository>()
    private val webAuthnManager = mockk<WebAuthnManager>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test")
    private val useCase = RegisterPasskeyFinishUseCase(redisChallengeStore, credentialRepository, webAuthnManager, props)

    @Test
    fun `expired challenge propagates PASSKEY_CHALLENGE_EXPIRED`() {
        every { redisChallengeStore.getAndDeleteChallenge("session-1") } throws
            BadRequestException("Challenge expired", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)

        val ex = assertThrows<BadRequestException> {
            useCase.execute(RegisterPasskeyFinishUseCase.Command(
                userId = UUID.randomUUID(),
                sessionId = "session-1",
                clientDataJSON = "dGVzdA==",
                attestationObject = "dGVzdA==",
                displayName = null,
            ))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }

    @Test
    fun `webAuthnManager validation failure throws PASSKEY_ATTESTATION_FAILED`() {
        every { redisChallengeStore.getAndDeleteChallenge(any()) } returns ByteArray(32)
        every { webAuthnManager.verify(any<RegistrationRequest>(), any<RegistrationParameters>()) } throws
            RuntimeException("Attestation signature mismatch")

        val ex = assertThrows<BadRequestException> {
            useCase.execute(RegisterPasskeyFinishUseCase.Command(
                userId = UUID.randomUUID(),
                sessionId = "session-2",
                clientDataJSON = "dGVzdA==",
                attestationObject = "dGVzdA==",
                displayName = null,
            ))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_ATTESTATION_FAILED)
    }
}
