package com.aibles.iam.authentication.domain.passkey

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface PasskeyCredentialRepository : JpaRepository<PasskeyCredential, UUID> {
    fun findByCredentialId(credentialId: ByteArray): PasskeyCredential?
    fun findAllByUserId(userId: UUID): List<PasskeyCredential>
}
