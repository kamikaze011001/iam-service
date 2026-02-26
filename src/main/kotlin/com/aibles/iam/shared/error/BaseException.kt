package com.aibles.iam.shared.error

import org.springframework.http.HttpStatus

abstract class BaseException(
    val errorCode: ErrorCode,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    val httpStatus: HttpStatus get() = errorCode.httpStatus
}
