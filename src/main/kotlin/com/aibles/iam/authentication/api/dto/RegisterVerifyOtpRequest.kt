package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern

data class RegisterVerifyOtpRequest(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Must be a valid email address")
    val email: String,
    @field:Pattern(regexp = "\\d{6}", message = "OTP must be exactly 6 digits")
    val code: String,
)
