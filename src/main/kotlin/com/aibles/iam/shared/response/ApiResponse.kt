package com.aibles.iam.shared.response

import java.time.Instant

data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val error: ErrorDetail? = null,
    val timestamp: Instant = Instant.now(),
) {
    companion object {
        fun <T> ok(data: T): ApiResponse<T> = ApiResponse(success = true, data = data)
        fun error(code: String, message: String): ApiResponse<Nothing> =
            ApiResponse(success = false, error = ErrorDetail(code, message))
    }
}

data class ErrorDetail(val code: String, val message: String)
