package com.aibles.iam.authentication.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import java.time.Instant

class SyncGoogleUserUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val useCase = SyncGoogleUserUseCase(userRepository, createUserUseCase)

    private fun oidcUser(sub: String, email: String, name: String? = "Test User"): DefaultOidcUser {
        val claims = mutableMapOf<String, Any>("sub" to sub, "iss" to "https://accounts.google.com")
        val idToken = OidcIdToken("token-value", Instant.now(), Instant.now().plusSeconds(3600), claims)
        val userInfoClaims = mutableMapOf<String, Any>("sub" to sub, "email" to email)
        if (name != null) userInfoClaims["name"] = name
        val userInfo = OidcUserInfo(userInfoClaims)
        return DefaultOidcUser(listOf(OidcUserAuthority(idToken, userInfo)), idToken, userInfo, "sub")
    }

    @Test
    fun `new user is created when neither googleSub nor email match`() {
        val oidcUser = oidcUser("sub-new", "new@example.com")
        val newUser = User.create("new@example.com", "Test User", "sub-new")
        every { userRepository.findByGoogleSub("sub-new") } returns null
        every { userRepository.findByEmail("new@example.com") } returns null
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(newUser)
        every { userRepository.save(newUser) } returns newUser

        val result = useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))

        assertThat(result.user.email).isEqualTo("new@example.com")
        verify(exactly = 1) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `email-matched user gets googleSub linked and saved`() {
        val oidcUser = oidcUser("sub-link", "preexisting@example.com")
        val existingUser = User.create("preexisting@example.com", "Pre User")   // googleSub is null
        assertThat(existingUser.googleSub).isNull()

        every { userRepository.findByGoogleSub("sub-link") } returns null
        every { userRepository.findByEmail("preexisting@example.com") } returns existingUser
        val savedSlot = slot<User>()
        every { userRepository.save(capture(savedSlot)) } returns existingUser

        useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))

        assertThat(savedSlot.captured.googleSub).isEqualTo("sub-link")
        verify(exactly = 0) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `existing user found by googleSub is returned without creating`() {
        val existingUser = User.create("existing@example.com", "Alice", "sub-existing")
        val oidcUser = oidcUser("sub-existing", "existing@example.com")
        every { userRepository.findByGoogleSub("sub-existing") } returns existingUser
        every { userRepository.save(existingUser) } returns existingUser

        val result = useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))

        assertThat(result.user.email).isEqualTo("existing@example.com")
        verify(exactly = 0) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `disabled user throws ForbiddenException`() {
        val disabledUser = User.create("disabled@example.com").also { it.disable() }
        val oidcUser = oidcUser("sub-d", "disabled@example.com")
        every { userRepository.findByGoogleSub("sub-d") } returns disabledUser
        every { userRepository.save(disabledUser) } returns disabledUser

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
    }
}
