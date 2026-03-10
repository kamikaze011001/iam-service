package com.aibles.iam.identity.infra

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.ApplicationArguments

class AdminBootstrapRunnerTest {

    private val userRepository = mockk<UserRepository>()
    private val args = mockk<ApplicationArguments>(relaxed = true)

    private fun runner(email: String) = AdminBootstrapRunner(userRepository, email)

    @Test
    fun `does nothing when adminEmail is blank`() {
        runner("").run(args)
        verify(exactly = 0) { userRepository.findByEmail(any()) }
    }

    @Test
    fun `does nothing when user is not found`() {
        every { userRepository.findByEmail("admin@example.com") } returns null
        runner("admin@example.com").run(args)
        verify(exactly = 0) { userRepository.save(any()) }
    }

    @Test
    fun `does nothing when user already has ADMIN role`() {
        val user = User.create("admin@example.com").apply { roles.add("ADMIN") }
        every { userRepository.findByEmail("admin@example.com") } returns user
        runner("admin@example.com").run(args)
        verify(exactly = 0) { userRepository.save(any()) }
        assertThat(user.roles).containsExactlyInAnyOrder("USER", "ADMIN")
    }

    @Test
    fun `promotes user to ADMIN when user exists without ADMIN role`() {
        val user = User.create("admin@example.com")
        every { userRepository.findByEmail("admin@example.com") } returns user
        every { userRepository.save(user) } returns user
        runner("admin@example.com").run(args)
        assertThat(user.roles).contains("ADMIN")
        verify { userRepository.save(user) }
    }
}
