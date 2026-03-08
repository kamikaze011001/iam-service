package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class FinishRegistrationUseCaseTest {

    private val ceremonyService = mockk<WebAuthnCeremonyService>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val credentialRepository = mockk<PasskeyCredentialRepository>(relaxed = true)
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val challengeStore = mockk<RedisChallengeStore>()
    private val useCase = FinishRegistrationUseCase(
        ceremonyService, createUserUseCase, credentialRepository, issueTokenUseCase, challengeStore
    )

    @Test
    fun `creates user and passkey and issues tokens`() {
        val userId = UUID.randomUUID()
        val user = mockk<User> {
            every { id } returns userId
            every { email } returns "new@test.com"
            every { roles } returns mutableSetOf("USER")
        }
        every { challengeStore.consumeSessionData("s1", "email") } returns "new@test.com"
        every { credentialRepository.save(any<PasskeyCredential>()) } answers { firstArg() }
        every { ceremonyService.verifyAttestation("s1", "cdj", "ao") } returns
            WebAuthnCeremonyService.VerifiedCredential(
                credentialId = byteArrayOf(1, 2, 3),
                publicKeyCose = byteArrayOf(4, 5, 6),
                signCounter = 0L,
                aaguid = null,
            )
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(user)
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("jwt", "rt", 900L)

        val result = useCase.execute(
            FinishRegistrationUseCase.Command(
                sessionId = "s1",
                clientDataJSON = "cdj",
                attestationObject = "ao",
                displayName = "Key",
            )
        )

        assertThat(result.accessToken).isEqualTo("jwt")
        assertThat(result.refreshToken).isEqualTo("rt")
        verify { credentialRepository.save(any()) }
    }

    @Test
    fun `throws when CreateUserUseCase throws USER_EMAIL_CONFLICT`() {
        every { challengeStore.consumeSessionData("s1", "email") } returns "dup@test.com"
        every { ceremonyService.verifyAttestation("s1", "cdj", "ao") } returns
            WebAuthnCeremonyService.VerifiedCredential(byteArrayOf(1), byteArrayOf(2), 0L, null)
        every { createUserUseCase.execute(any()) } throws
            ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)

        assertThatThrownBy {
            useCase.execute(FinishRegistrationUseCase.Command("s1", "cdj", "ao", null))
        }
            .isInstanceOf(ConflictException::class.java)

        verify(exactly = 0) { credentialRepository.save(any()) }
    }

    @Test
    fun `result includes userId and email`() {
        val userId = UUID.randomUUID()
        val user = mockk<User> {
            every { id } returns userId
            every { email } returns "test@example.com"
            every { roles } returns mutableSetOf("USER")
        }
        every { challengeStore.consumeSessionData(any(), "email") } returns "test@example.com"
        every { ceremonyService.verifyAttestation(any(), any(), any()) } returns
            WebAuthnCeremonyService.VerifiedCredential(byteArrayOf(1), byteArrayOf(2), 0L, null)
        every { credentialRepository.save(any<PasskeyCredential>()) } answers { firstArg() }
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(user)
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(
            FinishRegistrationUseCase.Command("session-id", "cdj-base64", "att-base64", null)
        )

        assertThat(result.userId).isEqualTo(userId)
        assertThat(result.email).isEqualTo("test@example.com")
        assertThat(result.accessToken).isEqualTo("access")
        assertThat(result.refreshToken).isEqualTo("refresh")
    }

    @Test
    fun `throws when session expired`() {
        every { challengeStore.consumeSessionData(any(), "email") } returns null

        assertThrows<BadRequestException> {
            useCase.execute(FinishRegistrationUseCase.Command("bad-session", "cdj", "att", null))
        }
    }
}
