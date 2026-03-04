package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class RegisterPasskeyFinishUseCase(
    private val credentialRepository: PasskeyCredentialRepository,
    private val ceremonyService: WebAuthnCeremonyService,
) {

    data class Command(
        val userId: UUID,
        val sessionId: String,
        val clientDataJSON: String,
        val attestationObject: String,
        val displayName: String?,
    )

    fun execute(command: Command) {
        val credential = ceremonyService.verifyAttestation(
            command.sessionId, command.clientDataJSON, command.attestationObject
        )
        credentialRepository.save(
            PasskeyCredential(
                userId = command.userId,
                credentialId = credential.credentialId,
                publicKeyCose = credential.publicKeyCose,
                signCounter = credential.signCounter,
                aaguid = credential.aaguid,
                displayName = command.displayName,
            )
        )
    }
}
