package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class RegisterStartRequest(
    val displayName: String? = null,
    @field:NotBlank(message = "otpToken is required")
    val otpToken: String,
)
