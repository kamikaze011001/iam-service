package com.aibles.iam.authentication.api.dto

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import java.time.Instant
import java.util.Base64
import java.util.UUID

data class PasskeyCredentialResponse(
    val id: UUID,
    val credentialId: String,
    val displayName: String?,
    val createdAt: Instant,
    val lastUsedAt: Instant?,
) {
    companion object {
        fun from(cred: PasskeyCredential) = PasskeyCredentialResponse(
            id = cred.id,
            credentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(cred.credentialId),
            displayName = cred.displayName,
            createdAt = cred.createdAt,
            lastUsedAt = cred.lastUsedAt,
        )
    }
}
