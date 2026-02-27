package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class AuthenticateFinishRequest(
    @field:NotBlank val credentialId: String,
    @field:NotBlank val sessionId: String,
    @field:NotBlank val clientDataJSON: String,
    @field:NotBlank val authenticatorData: String,
    @field:NotBlank val signature: String,
    val userHandle: String? = null,
)
