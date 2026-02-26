package com.aibles.iam.identity.api.dto

import jakarta.validation.constraints.NotBlank

data class UpdateUserRequest(
    @field:NotBlank val displayName: String,
)
