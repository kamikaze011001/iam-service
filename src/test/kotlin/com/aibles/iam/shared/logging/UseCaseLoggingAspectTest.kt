package com.aibles.iam.shared.logging

import com.aibles.iam.fake.usecase.FakeUseCase
import com.aibles.iam.shared.error.BadRequestException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.EnableAspectJAutoProxy
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [UseCaseLoggingAspectTest.TestConfig::class])
class UseCaseLoggingAspectTest {

    @Configuration
    @EnableAspectJAutoProxy
    class TestConfig {
        @Bean fun fakeUseCase() = FakeUseCase()
        @Bean fun useCaseLoggingAspect() = UseCaseLoggingAspect()
    }

    @Autowired
    lateinit var fakeUseCase: FakeUseCase

    @Test
    fun `aspect intercepts execute and returns result`() {
        val result = fakeUseCase.execute("hello")
        assert(result == "result-hello")
    }

    @Test
    fun `aspect re-throws BaseException`() {
        assertThrows<BadRequestException> {
            fakeUseCase.executeThrowingBase()
        }
    }

    @Test
    fun `aspect re-throws unexpected RuntimeException`() {
        assertThrows<RuntimeException> {
            fakeUseCase.executeThrowingUnexpected()
        }
    }
}
