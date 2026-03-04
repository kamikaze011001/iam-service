package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class RegisterPasskeyFinishUseCaseTest {

    private val credentialRepository = mockk<PasskeyCredentialRepository>(relaxed = true)
    private val ceremonyService = mockk<WebAuthnCeremonyService>()
    private val useCase = RegisterPasskeyFinishUseCase(credentialRepository, ceremonyService)

    @Test
    fun `expired challenge propagates PASSKEY_CHALLENGE_EXPIRED`() {
        every { ceremonyService.verifyAttestation("session-1", any(), any()) } throws
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
        every { ceremonyService.verifyAttestation("session-2", any(), any()) } throws
            BadRequestException("Passkey attestation failed: Attestation signature mismatch", ErrorCode.PASSKEY_ATTESTATION_FAILED)

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
