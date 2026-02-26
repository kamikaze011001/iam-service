package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class CreateUserUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val useCase = CreateUserUseCase(repo)

    @Test
    fun `creates and saves user`() {
        every { repo.existsByEmail("a@b.com") } returns false
        every { repo.save(any()) } answers { firstArg() }

        val result = useCase.execute(CreateUserUseCase.Command("a@b.com", "Alice", null))

        assertThat(result.user.email).isEqualTo("a@b.com")
        assertThat(result.user.displayName).isEqualTo("Alice")
        verify(exactly = 1) { repo.save(any()) }
    }

    @Test
    fun `throws ConflictException for duplicate email`() {
        every { repo.existsByEmail(any()) } returns true

        val ex = assertThrows<ConflictException> {
            useCase.execute(CreateUserUseCase.Command("a@b.com", null, null))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_EMAIL_CONFLICT)
    }
}
