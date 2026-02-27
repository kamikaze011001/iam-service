package com.aibles.iam.authentication.api.dto

data class TokenResponse(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Long,
)
