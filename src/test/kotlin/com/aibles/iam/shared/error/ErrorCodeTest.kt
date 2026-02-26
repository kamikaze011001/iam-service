package com.aibles.iam.shared.error

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ErrorCodeTest {

    @Test
    fun `USER_NOT_FOUND maps to 404`() =
        assertThat(ErrorCode.USER_NOT_FOUND.httpStatus.value()).isEqualTo(404)

    @Test
    fun `TOKEN_INVALID maps to 401`() =
        assertThat(ErrorCode.TOKEN_INVALID.httpStatus.value()).isEqualTo(401)

    @Test
    fun `USER_EMAIL_CONFLICT maps to 409`() =
        assertThat(ErrorCode.USER_EMAIL_CONFLICT.httpStatus.value()).isEqualTo(409)

    @Test
    fun `USER_DISABLED maps to 403`() =
        assertThat(ErrorCode.USER_DISABLED.httpStatus.value()).isEqualTo(403)

    @Test
    fun `VALIDATION_ERROR maps to 422`() =
        assertThat(ErrorCode.VALIDATION_ERROR.httpStatus.value()).isEqualTo(422)

    @Test
    fun `PASSKEY_CHALLENGE_EXPIRED maps to 400`() =
        assertThat(ErrorCode.PASSKEY_CHALLENGE_EXPIRED.httpStatus.value()).isEqualTo(400)

    @Test
    fun `PASSKEY_COUNTER_INVALID maps to 401`() =
        assertThat(ErrorCode.PASSKEY_COUNTER_INVALID.httpStatus.value()).isEqualTo(401)

    @Test
    fun `PASSKEY_NOT_FOUND maps to 404`() =
        assertThat(ErrorCode.PASSKEY_NOT_FOUND.httpStatus.value()).isEqualTo(404)

    @Test
    fun `GOOGLE_TOKEN_INVALID maps to 401`() =
        assertThat(ErrorCode.GOOGLE_TOKEN_INVALID.httpStatus.value()).isEqualTo(401)

    @Test
    fun `INTERNAL_ERROR maps to 500`() =
        assertThat(ErrorCode.INTERNAL_ERROR.httpStatus.value()).isEqualTo(500)

    @Test
    fun `exception httpStatus derived from errorCode`() {
        val ex = NotFoundException("not found", ErrorCode.USER_NOT_FOUND)
        assertThat(ex.httpStatus.value()).isEqualTo(404)
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }

    @Test
    fun `ValidationException always uses VALIDATION_ERROR code`() {
        val ex = ValidationException("invalid", mapOf("email" to "required"))
        assertThat(ex.errorCode).isEqualTo(ErrorCode.VALIDATION_ERROR)
        assertThat(ex.httpStatus.value()).isEqualTo(422)
        assertThat(ex.fields["email"]).isEqualTo("required")
    }

    @Test
    fun `ConflictException carries errorCode`() {
        val ex = ConflictException("email taken", ErrorCode.USER_EMAIL_CONFLICT)
        assertThat(ex.httpStatus.value()).isEqualTo(409)
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_EMAIL_CONFLICT)
    }

    @Test
    fun `UnauthorizedException carries errorCode`() {
        val ex = UnauthorizedException("bad token", ErrorCode.TOKEN_INVALID)
        assertThat(ex.httpStatus.value()).isEqualTo(401)
    }

    @Test
    fun `ForbiddenException carries errorCode`() {
        val ex = ForbiddenException("disabled", ErrorCode.USER_DISABLED)
        assertThat(ex.httpStatus.value()).isEqualTo(403)
    }

    @Test
    fun `BadRequestException carries errorCode`() {
        val ex = BadRequestException("bad input", ErrorCode.BAD_REQUEST)
        assertThat(ex.httpStatus.value()).isEqualTo(400)
    }
}
