package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class RegisterFinishRequest(
    @field:NotBlank val sessionId: String,
    @field:NotBlank val clientDataJSON: String,
    @field:NotBlank val attestationObject: String,
    val displayName: String? = null,
)
