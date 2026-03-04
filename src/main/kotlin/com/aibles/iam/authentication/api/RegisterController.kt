package com.aibles.iam.authentication.api

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.api.dto.RegisterFinishRequest
import com.aibles.iam.authentication.api.dto.RegisterSendOtpRequest
import com.aibles.iam.authentication.api.dto.RegisterStartRequest
import com.aibles.iam.authentication.api.dto.RegisterVerifyOtpRequest
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.api.dto.VerifyOtpResponse
import com.aibles.iam.authentication.usecase.FinishRegistrationUseCase
import com.aibles.iam.authentication.usecase.SendRegistrationOtpUseCase
import com.aibles.iam.authentication.usecase.StartRegistrationUseCase
import com.aibles.iam.authentication.usecase.VerifyRegistrationOtpUseCase
import com.aibles.iam.shared.response.ApiResponse
import jakarta.validation.Valid
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth/register")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Registration", description = "Email + passkey self-registration")
class RegisterController(
    private val sendRegistrationOtpUseCase: SendRegistrationOtpUseCase,
    private val verifyRegistrationOtpUseCase: VerifyRegistrationOtpUseCase,
    private val startRegistrationUseCase: StartRegistrationUseCase,
    private val finishRegistrationUseCase: FinishRegistrationUseCase,
    private val eventPublisher: ApplicationEventPublisher,
) {

    @PostMapping("/send-otp")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun sendOtp(@Valid @RequestBody request: RegisterSendOtpRequest): ApiResponse<Unit> {
        sendRegistrationOtpUseCase.execute(SendRegistrationOtpUseCase.Command(request.email))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.REGISTRATION_OTP_SENT,
            metadata = mapOf("email" to request.email.lowercase().trim()),
        ))
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/verify-otp")
    fun verifyOtp(@Valid @RequestBody request: RegisterVerifyOtpRequest): ApiResponse<VerifyOtpResponse> {
        val result = verifyRegistrationOtpUseCase.execute(
            VerifyRegistrationOtpUseCase.Command(request.email, request.code)
        )
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.REGISTRATION_OTP_VERIFIED,
            metadata = mapOf("email" to request.email.lowercase().trim()),
        ))
        return ApiResponse.ok(VerifyOtpResponse(result.otpToken))
    }

    @PostMapping("/passkey/start")
    fun passkeyStart(@Valid @RequestBody request: RegisterStartRequest): ApiResponse<StartRegistrationUseCase.Result> {
        val result = startRegistrationUseCase.execute(
            StartRegistrationUseCase.Command(request.otpToken, request.displayName)
        )
        return ApiResponse.ok(result)
    }

    @PostMapping("/passkey/finish")
    fun passkeyFinish(@Valid @RequestBody request: RegisterFinishRequest): ApiResponse<TokenResponse> {
        val result = finishRegistrationUseCase.execute(
            FinishRegistrationUseCase.Command(
                sessionId = request.sessionId,
                clientDataJSON = request.clientDataJSON,
                attestationObject = request.attestationObject,
                displayName = request.displayName,
            )
        )
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.REGISTRATION_COMPLETED,
        ))
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }
}
