package com.aibles.iam.authentication.api

import com.aibles.iam.authentication.api.dto.LogoutRequest
import com.aibles.iam.authentication.api.dto.RefreshTokenRequest
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.shared.response.ApiResponse
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Auth", description = "Token refresh and logout")
class AuthController(
    private val refreshTokenUseCase: RefreshTokenUseCase,
    private val revokeTokenUseCase: RevokeTokenUseCase,
) {

    @PostMapping("/refresh")
    fun refresh(@Valid @RequestBody request: RefreshTokenRequest): ApiResponse<TokenResponse> {
        val result = refreshTokenUseCase.execute(RefreshTokenUseCase.Command(request.refreshToken))
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun logout(@Valid @RequestBody request: LogoutRequest) {
        revokeTokenUseCase.execute(RevokeTokenUseCase.Command(request.refreshToken))
    }
}
