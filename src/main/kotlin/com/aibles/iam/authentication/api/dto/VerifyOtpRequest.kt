package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.Pattern

data class VerifyOtpRequest(
    @field:Pattern(regexp = "\\d{6}", message = "OTP must be exactly 6 digits")
    val code: String,
)
