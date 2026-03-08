package com.aibles.iam.authentication.api

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.api.dto.AuthenticateFinishRequest
import com.aibles.iam.authentication.api.dto.PasskeyCredentialResponse
import com.aibles.iam.authentication.api.dto.RegisterFinishRequest
import com.aibles.iam.authentication.api.dto.RegisterStartRequest
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.api.dto.VerifyOtpRequest
import com.aibles.iam.authentication.api.dto.VerifyOtpResponse
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
import com.aibles.iam.authentication.usecase.SendPasskeyOtpUseCase
import com.aibles.iam.authentication.usecase.VerifyPasskeyOtpUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.response.ApiResponse
import com.aibles.iam.shared.web.HttpContextExtractor
import jakarta.validation.Valid
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/auth/passkey")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Passkey", description = "WebAuthn passkey registration and authentication")
class PasskeyController(
    private val registerPasskeyStartUseCase: RegisterPasskeyStartUseCase,
    private val registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase,
    private val authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase,
    private val authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase,
    private val deletePasskeyUseCase: DeletePasskeyUseCase,
    private val credentialRepository: PasskeyCredentialRepository,
    private val getUserUseCase: GetUserUseCase,
    private val sendPasskeyOtpUseCase: SendPasskeyOtpUseCase,
    private val verifyPasskeyOtpUseCase: VerifyPasskeyOtpUseCase,
    private val eventPublisher: ApplicationEventPublisher,
    private val httpContextExtractor: HttpContextExtractor,
) {

    @PostMapping("/register/send-otp")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun sendOtp(@AuthenticationPrincipal principal: Jwt): ApiResponse<Unit> {
        val userId = UUID.fromString(principal.subject)
        sendPasskeyOtpUseCase.execute(SendPasskeyOtpUseCase.Command(userId))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.PASSKEY_OTP_SENT,
            userId = userId,
            actorId = userId,
            ipAddress = httpContextExtractor.clientIp(),
            userAgent = httpContextExtractor.userAgent(),
        ))
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/register/verify-otp")
    fun verifyOtp(
        @AuthenticationPrincipal principal: Jwt,
        @Valid @RequestBody request: VerifyOtpRequest,
    ): ApiResponse<VerifyOtpResponse> {
        val userId = UUID.fromString(principal.subject)
        val result = verifyPasskeyOtpUseCase.execute(
            VerifyPasskeyOtpUseCase.Command(userId, request.code)
        )
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.PASSKEY_OTP_VERIFIED,
            userId = userId,
            actorId = userId,
            ipAddress = httpContextExtractor.clientIp(),
            userAgent = httpContextExtractor.userAgent(),
        ))
        return ApiResponse.ok(VerifyOtpResponse(result.otpToken))
    }

    @PostMapping("/register/start")
    fun registerStart(
        @AuthenticationPrincipal principal: Jwt,
        @Valid @RequestBody request: RegisterStartRequest,
    ): ApiResponse<RegisterPasskeyStartUseCase.Result> {
        val userId = UUID.fromString(principal.subject)
        val user = getUserUseCase.execute(GetUserUseCase.Query(userId))
        val result = registerPasskeyStartUseCase.execute(
            RegisterPasskeyStartUseCase.Command(
                userId = userId,
                userEmail = user.email,
                displayName = request.displayName,
                otpToken = request.otpToken,
            )
        )
        return ApiResponse.ok(result)
    }

    @PostMapping("/register/finish")
    fun registerFinish(
        @AuthenticationPrincipal principal: Jwt,
        @Valid @RequestBody request: RegisterFinishRequest,
    ): ApiResponse<Unit> {
        val userId = UUID.fromString(principal.subject)
        registerPasskeyFinishUseCase.execute(
            RegisterPasskeyFinishUseCase.Command(
                userId = userId,
                sessionId = request.sessionId,
                clientDataJSON = request.clientDataJSON,
                attestationObject = request.attestationObject,
                displayName = request.displayName,
            )
        )
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.PASSKEY_REGISTERED,
            userId = userId,
            actorId = userId,
            ipAddress = httpContextExtractor.clientIp(),
            userAgent = httpContextExtractor.userAgent(),
            metadata = request.displayName?.let { mapOf("displayName" to it) },
        ))
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/authenticate/start")
    fun authenticateStart(): ApiResponse<AuthenticatePasskeyStartUseCase.Result> =
        ApiResponse.ok(authenticatePasskeyStartUseCase.execute())

    @PostMapping("/authenticate/finish")
    fun authenticateFinish(
        @Valid @RequestBody request: AuthenticateFinishRequest,
    ): ApiResponse<TokenResponse> {
        val result = authenticatePasskeyFinishUseCase.execute(
            AuthenticatePasskeyFinishUseCase.Command(
                credentialId = request.credentialId,
                sessionId = request.sessionId,
                clientDataJSON = request.clientDataJSON,
                authenticatorData = request.authenticatorData,
                signature = request.signature,
                userHandle = request.userHandle,
            )
        )
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.PASSKEY_AUTHENTICATED,
            userId = result.userId,
            actorId = result.userId,
            ipAddress = httpContextExtractor.clientIp(),
            userAgent = httpContextExtractor.userAgent(),
        ))
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }

    @GetMapping("/credentials")
    fun listCredentials(
        @AuthenticationPrincipal principal: Jwt,
    ): ApiResponse<List<PasskeyCredentialResponse>> {
        val userId = UUID.fromString(principal.subject)
        val credentials = credentialRepository.findAllByUserId(userId)
            .map { PasskeyCredentialResponse.from(it) }
        return ApiResponse.ok(credentials)
    }

    @DeleteMapping("/credentials/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteCredential(
        @AuthenticationPrincipal principal: Jwt,
        @PathVariable id: UUID,
    ) {
        val userId = UUID.fromString(principal.subject)
        deletePasskeyUseCase.execute(DeletePasskeyUseCase.Command(userId, id))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.PASSKEY_DELETED,
            userId = userId,
            actorId = userId,
            ipAddress = httpContextExtractor.clientIp(),
            userAgent = httpContextExtractor.userAgent(),
            metadata = mapOf("credentialId" to id.toString()),
        ))
    }
}
