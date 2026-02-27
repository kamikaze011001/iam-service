package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import java.time.Instant

class LoginWithGoogleUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val useCase = LoginWithGoogleUseCase(userRepository, createUserUseCase, issueTokenUseCase)

    private fun oidcUser(sub: String, email: String, name: String? = "Test User"): DefaultOidcUser {
        val claims = mutableMapOf<String, Any>(
            "sub" to sub,
            "iss" to "https://accounts.google.com",
        )
        val idToken = OidcIdToken("token-value", Instant.now(), Instant.now().plusSeconds(3600), claims)
        val userInfoClaims = mutableMapOf<String, Any>(
            "sub" to sub,
            "email" to email,
        )
        if (name != null) userInfoClaims["name"] = name
        val userInfo = OidcUserInfo(userInfoClaims)
        val authority = OidcUserAuthority(idToken, userInfo)
        return DefaultOidcUser(listOf(authority), idToken, userInfo, "sub")
    }

    @Test
    fun `new user is created on first Google login`() {
        val oidcUser = oidcUser("sub-new", "new@example.com", "New User")
        val newUser = User.create("new@example.com", "New User")
        every { userRepository.findByGoogleSub("sub-new") } returns null
        every { userRepository.findByEmail("new@example.com") } returns null
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(newUser)
        every { userRepository.save(newUser) } returns newUser
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))

        assertThat(result.accessToken).isEqualTo("access")
        verify(exactly = 1) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `existing user by googleSub is returned on second login without creating new user`() {
        val existingUser = User.create("existing@example.com", "Alice", "sub-existing")
        val oidcUser = oidcUser("sub-existing", "existing@example.com", "Alice")
        every { userRepository.findByGoogleSub("sub-existing") } returns existingUser
        every { userRepository.save(existingUser) } returns existingUser
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access2", "refresh2", 900)

        val result = useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))

        assertThat(result.accessToken).isEqualTo("access2")
        verify(exactly = 0) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `disabled user throws ForbiddenException with USER_DISABLED`() {
        val disabledUser = User.create("disabled@example.com").also { it.disable() }
        val oidcUser = oidcUser("sub-disabled", "disabled@example.com")
        every { userRepository.findByGoogleSub("sub-disabled") } returns disabledUser
        every { userRepository.save(disabledUser) } returns disabledUser

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
    }
}
