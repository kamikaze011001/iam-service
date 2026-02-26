package com.aibles.iam.identity.domain.user

import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserRepository : JpaRepository<User, UUID> {
    fun existsByEmail(email: String): Boolean
    fun findByEmail(email: String): User?
    fun findByGoogleSub(googleSub: String): User?
    override fun findAll(pageable: Pageable): Page<User>
}
