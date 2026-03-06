package com.aibles.iam.fake.usecase

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class FakeUseCase {
    fun execute(input: String): String = "result-$input"
    fun executeThrowingBase(): Nothing = throw BadRequestException("bad input", ErrorCode.BAD_REQUEST)
    fun executeThrowingUnexpected(): Nothing = throw RuntimeException("unexpected")
}
