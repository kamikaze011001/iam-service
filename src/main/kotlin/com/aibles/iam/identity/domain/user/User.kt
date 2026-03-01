package com.aibles.iam.identity.domain.user

import jakarta.persistence.CollectionTable
import jakarta.persistence.Column
import jakarta.persistence.ElementCollection
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.FetchType
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "users")
class User private constructor(
    @Id val id: UUID = UUID.randomUUID(),
    @Column(unique = true, nullable = false) val email: String,
    var displayName: String? = null,
    @Column(unique = true) var googleSub: String? = null,
    @Enumerated(EnumType.STRING) var status: UserStatus = UserStatus.ACTIVE,
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = [JoinColumn(name = "user_id")])
    @Column(name = "role") var roles: MutableSet<String> = mutableSetOf("USER"),
    val createdAt: Instant = Instant.now(),
    var updatedAt: Instant = Instant.now(),
    var lastLoginAt: Instant? = null,
) {
    // Required by JPA
    protected constructor() : this(email = "")

    companion object {
        fun create(email: String, displayName: String? = null, googleSub: String? = null): User {
            require(email.isNotBlank() && email.contains("@")) { "Invalid email: $email" }
            return User(
                email = email.lowercase().trim(),
                displayName = displayName?.trim(),
                googleSub = googleSub,
            )
        }
    }

    fun updateProfile(newDisplayName: String) {
        displayName = newDisplayName.trim()
        updatedAt = Instant.now()
    }

    fun disable() {
        status = UserStatus.DISABLED
        updatedAt = Instant.now()
    }

    fun enable() {
        status = UserStatus.ACTIVE
        updatedAt = Instant.now()
    }

    fun recordLogin() {
        lastLoginAt = Instant.now()
        updatedAt = Instant.now()
    }

    fun linkGoogleAccount(googleSub: String) {
        this.googleSub = googleSub
        updatedAt = Instant.now()
    }

    fun isActive() = status == UserStatus.ACTIVE
}
