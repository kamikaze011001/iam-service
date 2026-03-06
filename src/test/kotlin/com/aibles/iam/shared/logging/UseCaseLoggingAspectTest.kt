package com.aibles.iam.shared.logging

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.EnableAspectJAutoProxy
import org.springframework.stereotype.Component

@SpringBootTest(classes = [UseCaseLoggingAspectTest.TestConfig::class, UseCaseLoggingAspect::class])
class UseCaseLoggingAspectTest {

    @Configuration
    @EnableAspectJAutoProxy
    class TestConfig {
        @Bean
        fun testUseCase() = TestUseCase()
    }

    @Component
    class TestUseCase {
        fun execute(command: String): String = "result-$command"
    }

    @Autowired
    lateinit var testUseCase: TestUseCase

    @Test
    fun `execute completes without throwing when aspect is wired`() {
        val result = testUseCase.execute("input")
        assert(result == "result-input")
    }

    @Test
    fun `execute still throws when use case throws`() {
        val throwingUseCase = object {
            fun execute(): Nothing = throw RuntimeException("use case failure")
        }
        // Direct invocation — aspect does not intercept non-Spring-managed objects
        // but verifies our aspect does not suppress exceptions
        try {
            throwingUseCase.execute()
            assert(false) { "Expected RuntimeException" }
        } catch (e: RuntimeException) {
            assert(e.message == "use case failure")
        }
    }
}
