package com.aibles.iam.shared.error

import com.aibles.iam.shared.response.ApiResponse
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {

    private val logger = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(BaseException::class)
    fun handleBase(e: BaseException): ResponseEntity<ApiResponse<Nothing>> {
        logger.warn("Domain exception [{}]: {}", e.errorCode, e.message)
        return ResponseEntity.status(e.httpStatus)
            .body(ApiResponse.error(e.errorCode.name, e.message ?: "Error"))
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(e: MethodArgumentNotValidException): ResponseEntity<ApiResponse<Nothing>> {
        val msg = e.bindingResult.fieldErrors.joinToString("; ") {
            "${it.field}: ${it.defaultMessage}"
        }
        logger.warn("Validation failed: {}", msg)
        return ResponseEntity.status(422)
            .body(ApiResponse.error(ErrorCode.VALIDATION_ERROR.name, msg))
    }

    @ExceptionHandler(Exception::class)
    fun handleUnexpected(e: Exception): ResponseEntity<ApiResponse<Nothing>> {
        logger.error("Unhandled exception", e)
        return ResponseEntity.internalServerError()
            .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.name, "Unexpected error"))
    }
}
