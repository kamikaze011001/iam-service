package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import java.util.UUID
import org.springframework.stereotype.Component

@Component
class FinishRegistrationUseCase(
    private val ceremonyService: WebAuthnCeremonyService,
    private val createUserUseCase: CreateUserUseCase,
    private val credentialRepository: PasskeyCredentialRepository,
    private val issueTokenUseCase: IssueTokenUseCase,
    private val challengeStore: RedisChallengeStore,
) {
    data class Command(
        val sessionId: String,
        val clientDataJSON: String,
        val attestationObject: String,
        val displayName: String?,
    )
    data class Result(
        val accessToken: String,
        val refreshToken: String,
        val expiresIn: Long,
        val userId: UUID,
        val email: String,
    )

    fun execute(command: Command): Result {
        // Retrieve the email stored during the start step
        val email = challengeStore.consumeSessionData(command.sessionId, "email")
            ?: throw BadRequestException("Registration session expired.", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)

        // Verify attestation (this also consumes the challenge)
        val credential = ceremonyService.verifyAttestation(
            command.sessionId, command.clientDataJSON, command.attestationObject
        )

        // Create user (throws USER_EMAIL_CONFLICT if race condition)
        val userResult = createUserUseCase.execute(
            CreateUserUseCase.Command(email = email, displayName = null, googleSub = null)
        )

        // Save passkey credential
        credentialRepository.save(
            PasskeyCredential(
                userId = userResult.user.id,
                credentialId = credential.credentialId,
                publicKeyCose = credential.publicKeyCose,
                signCounter = credential.signCounter,
                aaguid = credential.aaguid,
                displayName = command.displayName,
            )
        )

        // Issue tokens
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(userResult.user))
        return Result(
            accessToken = tokens.accessToken,
            refreshToken = tokens.refreshToken,
            expiresIn = tokens.expiresIn,
            userId = userResult.user.id,
            email = email,
        )
    }
}
