package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Optional
import java.util.UUID

class UpdateUserUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val useCase = UpdateUserUseCase(repo)

    @Test
    fun `updates display name and saves`() {
        val user = User.create("a@b.com", "Old Name")
        every { repo.findById(user.id) } returns Optional.of(user)
        every { repo.save(any()) } answers { firstArg() }

        val result = useCase.execute(UpdateUserUseCase.Command(user.id, "New Name"))

        assertThat(result.user.displayName).isEqualTo("New Name")
        verify(exactly = 1) { repo.save(user) }
    }

    @Test
    fun `throws NotFoundException when user not found`() {
        val id = UUID.randomUUID()
        every { repo.findById(id) } returns Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(UpdateUserUseCase.Command(id, "Name"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
