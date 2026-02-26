package com.aibles.iam.identity.api.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class CreateUserRequest(
    @field:NotBlank @field:Email val email: String,
    val displayName: String?,
)
