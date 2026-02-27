package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class RefreshTokenRequest(@field:NotBlank val refreshToken: String)
