package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import io.mockk.every
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

    private val syncGoogleUserUseCase = mockk<SyncGoogleUserUseCase>()
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val useCase = LoginWithGoogleUseCase(syncGoogleUserUseCase, issueTokenUseCase)

    private fun oidcUser(sub: String, email: String): DefaultOidcUser {
        val claims = mutableMapOf<String, Any>("sub" to sub, "iss" to "https://accounts.google.com")
        val idToken = OidcIdToken("token-value", Instant.now(), Instant.now().plusSeconds(3600), claims)
        val userInfoClaims = mutableMapOf<String, Any>("sub" to sub, "email" to email)
        val userInfo = OidcUserInfo(userInfoClaims)
        return DefaultOidcUser(listOf(OidcUserAuthority(idToken, userInfo)), idToken, userInfo, "sub")
    }

    @Test
    fun `delegates to syncGoogleUserUseCase and issues tokens`() {
        val user = User.create("test@example.com", "Test", "sub-1")
        val oidcUser = oidcUser("sub-1", "test@example.com")
        every { syncGoogleUserUseCase.execute(any()) } returns SyncGoogleUserUseCase.Result(user)
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))

        assertThat(result.accessToken).isEqualTo("access")
        assertThat(result.refreshToken).isEqualTo("refresh")
        assertThat(result.user).isEqualTo(user)
        verify(exactly = 1) { syncGoogleUserUseCase.execute(any()) }
        verify(exactly = 1) { issueTokenUseCase.execute(any()) }
    }

    @Test
    fun `propagates ForbiddenException from syncGoogleUserUseCase`() {
        val oidcUser = oidcUser("sub-d", "disabled@example.com")
        every { syncGoogleUserUseCase.execute(any()) } throws
            ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
        verify(exactly = 0) { issueTokenUseCase.execute(any()) }
    }
}
