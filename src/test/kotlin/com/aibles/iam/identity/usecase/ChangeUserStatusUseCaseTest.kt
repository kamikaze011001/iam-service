package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.domain.user.UserStatus
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

class ChangeUserStatusUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val useCase = ChangeUserStatusUseCase(repo)

    @Test
    fun `disables an active user`() {
        val user = User.create("a@b.com")
        every { repo.findById(user.id) } returns Optional.of(user)
        every { repo.save(any()) } answers { firstArg() }

        val result = useCase.execute(ChangeUserStatusUseCase.Command(user.id, UserStatus.DISABLED))

        assertThat(result.user.isActive()).isFalse()
        verify(exactly = 1) { repo.save(user) }
    }

    @Test
    fun `enables a disabled user`() {
        val user = User.create("a@b.com").also { it.disable() }
        every { repo.findById(user.id) } returns Optional.of(user)
        every { repo.save(any()) } answers { firstArg() }

        val result = useCase.execute(ChangeUserStatusUseCase.Command(user.id, UserStatus.ACTIVE))

        assertThat(result.user.isActive()).isTrue()
    }

    @Test
    fun `throws NotFoundException when user not found`() {
        val id = UUID.randomUUID()
        every { repo.findById(id) } returns Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(ChangeUserStatusUseCase.Command(id, UserStatus.DISABLED))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
