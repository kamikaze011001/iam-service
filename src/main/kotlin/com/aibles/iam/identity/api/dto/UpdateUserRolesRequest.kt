package com.aibles.iam.identity.api.dto

import jakarta.validation.constraints.NotEmpty

data class UpdateUserRolesRequest(
    @field:NotEmpty(message = "Roles must not be empty")
    val roles: Set<String>,
)
