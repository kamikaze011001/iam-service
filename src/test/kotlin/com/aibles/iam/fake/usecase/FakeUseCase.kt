package com.aibles.iam.fake.usecase

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class FakeUseCase {
    fun execute(command: String): String = when (command) {
        "throw-base" -> throw BadRequestException("bad input", ErrorCode.BAD_REQUEST)
        "throw-unexpected" -> throw RuntimeException("unexpected boom")
        else -> "result-$command"
    }
}
