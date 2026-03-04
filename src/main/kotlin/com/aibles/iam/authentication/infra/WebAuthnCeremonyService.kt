package com.aibles.iam.authentication.infra

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
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class WebAuthnCeremonyService(
    private val challengeStore: RedisChallengeStore,
    private val webAuthnManager: WebAuthnManager,
    private val props: WebAuthnProperties,
    private val objectConverter: ObjectConverter,
) {
    data class ChallengeData(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>> = listOf(
            mapOf("type" to "public-key", "alg" to -7),
            mapOf("type" to "public-key", "alg" to -257),
        ),
        val timeout: Int = 60_000,
        val attestation: String = "none",
    )

    data class VerifiedCredential(
        val credentialId: ByteArray,
        val publicKeyCose: ByteArray,
        val signCounter: Long,
        val aaguid: UUID?,
    )

    fun createChallenge(): ChallengeData {
        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        challengeStore.storeChallenge(sessionId, challengeBytes)
        return ChallengeData(
            sessionId = sessionId,
            rpId = props.rpId,
            rpName = props.rpName,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }

    fun verifyAttestation(sessionId: String, clientDataJSON: String, attestationObject: String): VerifiedCredential {
        val challenge = challengeStore.getAndDeleteChallenge(sessionId)

        val decoder = Base64.getUrlDecoder()
        val clientDataBytes = decoder.decode(clientDataJSON.padBase64Url())
        val attestationBytes = decoder.decode(attestationObject.padBase64Url())

        val registrationRequest = RegistrationRequest(attestationBytes, clientDataBytes)
        val serverProperty = ServerProperty(
            Origin.create(props.rpOrigin),
            props.rpId,
            DefaultChallenge(challenge),
            null,
        )
        val registrationParameters = RegistrationParameters(serverProperty, null, false, true)

        val data = try {
            webAuthnManager.verify(registrationRequest, registrationParameters)
        } catch (e: RuntimeException) {
            throw BadRequestException("Passkey attestation failed: ${e.message}", ErrorCode.PASSKEY_ATTESTATION_FAILED)
        }

        val authData = data.attestationObject!!.authenticatorData
        val credData = authData.attestedCredentialData!!
        val coseKeyBytes = objectConverter.cborConverter.writeValueAsBytes(credData.coseKey)
        val aaguid: UUID? = credData.aaguid.value?.let {
            try { UUID.fromString(it.toString()) } catch (_: Exception) { null }
        }

        return VerifiedCredential(
            credentialId = credData.credentialId,
            publicKeyCose = coseKeyBytes,
            signCounter = authData.signCount,
            aaguid = aaguid,
        )
    }

    private fun String.padBase64Url(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}
