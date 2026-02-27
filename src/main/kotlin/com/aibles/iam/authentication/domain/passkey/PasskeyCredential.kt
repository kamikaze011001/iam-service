package com.aibles.iam.authentication.domain.passkey

import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "passkey_credentials")
class PasskeyCredential(
    @Id val id: UUID = UUID.randomUUID(),
    @Column(name = "user_id", nullable = false) val userId: UUID,
    @Column(name = "credential_id", columnDefinition = "bytea", nullable = false, unique = true)
    var credentialId: ByteArray,
    @Column(name = "public_key_cose", columnDefinition = "bytea", nullable = false)
    var publicKeyCose: ByteArray,
    @Column(name = "sign_counter", nullable = false) var signCounter: Long = 0,
    @Column(name = "aaguid") var aaguid: UUID? = null,
    @Column(name = "display_name") var displayName: String? = null,
    @Column(name = "created_at", nullable = false) val createdAt: Instant = Instant.now(),
    @Column(name = "last_used_at") var lastUsedAt: Instant? = null,
) {
    // Required by JPA
    protected constructor() : this(userId = UUID.randomUUID(), credentialId = ByteArray(0), publicKeyCose = ByteArray(0))

    fun verifyAndIncrementCounter(newCounter: Long) {
        if (newCounter <= signCounter)
            throw UnauthorizedException("Counter replay detected", ErrorCode.PASSKEY_COUNTER_INVALID)
        signCounter = newCounter
    }
}
