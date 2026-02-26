package com.aibles.iam.identity.api.dto

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserStatus
import java.time.Instant
import java.util.UUID

data class UserResponse(
    val id: UUID,
    val email: String,
    val displayName: String?,
    val status: UserStatus,
    val createdAt: Instant,
    val updatedAt: Instant,
) {
    companion object {
        fun from(user: User) = UserResponse(
            id = user.id,
            email = user.email,
            displayName = user.displayName,
            status = user.status,
            createdAt = user.createdAt,
            updatedAt = user.updatedAt,
        )
    }
}
