package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import org.springframework.stereotype.Component
import java.util.Base64
import java.util.UUID

@Component
class RegisterPasskeyFinishUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val credentialRepository: PasskeyCredentialRepository,
    private val webAuthnManager: WebAuthnManager,
    private val props: WebAuthnProperties,
    private val objectConverter: ObjectConverter,
) {

    data class Command(
        val userId: UUID,
        val sessionId: String,
        val clientDataJSON: String,    // base64url from browser
        val attestationObject: String, // base64url from browser
        val displayName: String?,
    )

    fun execute(command: Command) {
        // Step 1: retrieve and consume challenge (throws PASSKEY_CHALLENGE_EXPIRED if missing)
        val challenge = redisChallengeStore.getAndDeleteChallenge(command.sessionId)

        // Step 2: decode browser response bytes (browsers send base64url without padding)
        val decoder = Base64.getUrlDecoder()
        val clientDataBytes = decoder.decode(command.clientDataJSON.padBase64Url())
        val attestationBytes = decoder.decode(command.attestationObject.padBase64Url())

        // Step 3: build webauthn4j request + parameters
        val registrationRequest = RegistrationRequest(attestationBytes, clientDataBytes)
        val serverProperty = ServerProperty(
            Origin.create(props.rpOrigin),
            props.rpId,
            DefaultChallenge(challenge),
            null,
        )
        val registrationParameters = RegistrationParameters(serverProperty, null, false, true)

        // Step 4: verify — throws VerificationException subclasses on failure
        val data = try {
            webAuthnManager.verify(registrationRequest, registrationParameters)
        } catch (e: RuntimeException) {
            throw BadRequestException("Passkey attestation failed: ${e.message}", ErrorCode.PASSKEY_ATTESTATION_FAILED)
        }

        // Step 5: extract credential data from verification result
        val authData = data.attestationObject!!.authenticatorData
        val credData = authData.attestedCredentialData!!
        val coseKeyBytes = objectConverter.cborConverter.writeValueAsBytes(credData.coseKey)
        val aaguid: UUID? = credData.aaguid.value?.let {
            try { UUID.fromString(it.toString()) } catch (_: Exception) { null }
        }

        // Step 6: save credential
        credentialRepository.save(
            PasskeyCredential(
                userId = command.userId,
                credentialId = credData.credentialId,
                publicKeyCose = coseKeyBytes,
                signCounter = authData.signCount,
                aaguid = aaguid,
                displayName = command.displayName,
            )
        )
    }

    // base64url strings from browsers may lack padding — add it before decoding
    private fun String.padBase64Url(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}
