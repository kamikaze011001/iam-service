package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class DeletePasskeyUseCase(private val credentialRepository: PasskeyCredentialRepository) {
    data class Command(val userId: UUID, val credentialId: UUID)

    fun execute(command: Command) {
        val credential = credentialRepository.findById(command.credentialId)
            .filter { it.userId == command.userId }
            .orElseThrow { NotFoundException("Passkey credential not found", ErrorCode.PASSKEY_NOT_FOUND) }
        credentialRepository.delete(credential)
    }
}
