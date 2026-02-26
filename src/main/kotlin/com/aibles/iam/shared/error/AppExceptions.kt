package com.aibles.iam.shared.error

class NotFoundException(message: String, errorCode: ErrorCode)    : BaseException(errorCode, message)
class ConflictException(message: String, errorCode: ErrorCode)     : BaseException(errorCode, message)
class UnauthorizedException(message: String, errorCode: ErrorCode) : BaseException(errorCode, message)
class ForbiddenException(message: String, errorCode: ErrorCode)    : BaseException(errorCode, message)
class BadRequestException(message: String, errorCode: ErrorCode)   : BaseException(errorCode, message)
class ValidationException(
    message: String,
    val fields: Map<String, String> = emptyMap(),
) : BaseException(ErrorCode.VALIDATION_ERROR, message)
