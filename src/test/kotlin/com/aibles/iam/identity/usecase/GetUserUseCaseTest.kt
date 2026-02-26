package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Optional
import java.util.UUID

class GetUserUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val useCase = GetUserUseCase(repo)

    @Test
    fun `returns user when found`() {
        val user = User.create("a@b.com")
        every { repo.findById(user.id) } returns Optional.of(user)

        assertThat(useCase.execute(GetUserUseCase.Query(user.id))).isEqualTo(user)
    }

    @Test
    fun `throws NotFoundException with USER_NOT_FOUND code`() {
        val id = UUID.randomUUID()
        every { repo.findById(id) } returns Optional.empty()

        val ex = assertThrows<NotFoundException> { useCase.execute(GetUserUseCase.Query(id)) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
