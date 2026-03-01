package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.error.UnauthorizedException
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.verifier.exception.MaliciousCounterValueException
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.Base64

@Component
class AuthenticatePasskeyFinishUseCase(
    private val credentialRepository: PasskeyCredentialRepository,
    private val redisChallengeStore: RedisChallengeStore,
    private val webAuthnManager: WebAuthnManager,
    private val getUserUseCase: GetUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
    private val props: WebAuthnProperties,
    private val objectConverter: ObjectConverter,
) {

    data class Command(
        val credentialId: String,   // base64url from browser
        val sessionId: String,
        val clientDataJSON: String,     // base64url
        val authenticatorData: String,  // base64url
        val signature: String,          // base64url
        val userHandle: String?,        // base64url, optional
    )
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val decoder = Base64.getUrlDecoder()

        // Step 1: look up stored credential
        val credIdBytes = decoder.decode(command.credentialId.padBase64Url())
        val credential = credentialRepository.findByCredentialId(credIdBytes)
            ?: throw NotFoundException("Passkey credential not found", ErrorCode.PASSKEY_NOT_FOUND)

        // Step 2: retrieve and consume challenge
        val challenge = redisChallengeStore.getAndDeleteChallenge(command.sessionId)

        // Step 3: reconstruct credential record for webauthn4j verification
        val coseKey = objectConverter.cborConverter.readValue(
            credential.publicKeyCose,
            com.webauthn4j.data.attestation.authenticator.COSEKey::class.java,
        )!!
        val aaguid = credential.aaguid?.let { AAGUID(it) } ?: AAGUID.ZERO
        val attestedCredentialData = AttestedCredentialData(aaguid, credential.credentialId, coseKey)
        val credentialRecord = CredentialRecordImpl(
            NoneAttestationStatement(),  // attestationStatement — not stored post-registration
            null,                        // uvInitialized — unknown from stored credential
            null,                        // backupEligible — unknown from stored credential
            null,                        // backupState — unknown from stored credential
            credential.signCounter,
            attestedCredentialData,
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput>(),
            null,                        // collectedClientData — not available at auth time
            null,                        // clientExtensions
            null,                        // authenticatorTransports
        )

        // Step 4: build authentication request + parameters
        val authRequest = AuthenticationRequest(
            credential.credentialId,
            command.userHandle?.let { decoder.decode(it.padBase64Url()) },
            decoder.decode(command.authenticatorData.padBase64Url()),
            decoder.decode(command.clientDataJSON.padBase64Url()),
            decoder.decode(command.signature.padBase64Url()),
        )
        val serverProperty = ServerProperty(
            Origin.create(props.rpOrigin),
            props.rpId,
            DefaultChallenge(challenge),
            null,
        )
        val authParameters = AuthenticationParameters(serverProperty, credentialRecord, null, false, true)

        // Step 5: verify assertion
        val authData = try {
            webAuthnManager.verify(authRequest, authParameters)
        } catch (_: MaliciousCounterValueException) {
            throw UnauthorizedException("Counter replay detected", ErrorCode.PASSKEY_COUNTER_INVALID)
        } catch (_: RuntimeException) {
            throw UnauthorizedException("Passkey assertion verification failed", ErrorCode.TOKEN_INVALID)
        }

        // Step 6: load user and verify account is active BEFORE modifying any credential state
        val user = getUserUseCase.execute(GetUserUseCase.Query(credential.userId))
        if (!user.isActive()) throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        // Step 7: update counter and last-used timestamp now that user is confirmed active
        credential.verifyAndIncrementCounter(authData.authenticatorData!!.signCount)
        credential.lastUsedAt = Instant.now()
        credentialRepository.save(credential)

        // Step 8: issue tokens
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }

    private fun String.padBase64Url(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}
