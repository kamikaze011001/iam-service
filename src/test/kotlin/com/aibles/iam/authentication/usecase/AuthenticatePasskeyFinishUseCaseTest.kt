package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.AuthenticationData
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.verifier.exception.MaliciousCounterValueException
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class AuthenticatePasskeyFinishUseCaseTest {

    private val credentialRepository = mockk<PasskeyCredentialRepository>()
    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val webAuthnManager = mockk<WebAuthnManager>()
    private val getUserUseCase = mockk<GetUserUseCase>()
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test")
    private val mockCborConverter = mockk<CborConverter>()
    private val objectConverter = mockk<ObjectConverter>().also {
        every { it.cborConverter } returns mockCborConverter
        every { mockCborConverter.readValue(any<ByteArray>(), COSEKey::class.java) } returns mockk(relaxed = true)
    }

    private val useCase = AuthenticatePasskeyFinishUseCase(
        credentialRepository, redisChallengeStore, webAuthnManager, getUserUseCase, issueTokenUseCase, props, objectConverter,
    )

    private val userId = UUID.randomUUID()
    private val credId = byteArrayOf(1, 2, 3)
    private val storedCredential = PasskeyCredential(
        userId = userId,
        credentialId = credId,
        publicKeyCose = byteArrayOf(4, 5, 6),
        signCounter = 5L,
    )

    private fun command(credentialId: String = "AQID", sessionId: String = "sess") =
        AuthenticatePasskeyFinishUseCase.Command(
            credentialId = credentialId,
            sessionId = sessionId,
            clientDataJSON = "dGVzdA==",
            authenticatorData = "dGVzdA==",
            signature = "dGVzdA==",
            userHandle = null,
        )

    @Test
    fun `happy path returns access and refresh tokens`() {
        val mockAuthData = mockk<AuthenticationData>(relaxed = true)
        every { mockAuthData.authenticatorData!!.signCount } returns 6L

        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge("sess") } returns ByteArray(32)
        every { webAuthnManager.verify(any<AuthenticationRequest>(), any<AuthenticationParameters>()) } returns mockAuthData
        every { credentialRepository.save(any()) } returns storedCredential
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns User.create("user@test.com", "Test User")
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(command())

        assertThat(result.accessToken).isEqualTo("access")
        assertThat(result.refreshToken).isEqualTo("refresh")
    }

    @Test
    fun `unknown credentialId throws PASSKEY_NOT_FOUND`() {
        every { credentialRepository.findByCredentialId(any()) } returns null

        val ex = assertThrows<NotFoundException> { useCase.execute(command()) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_NOT_FOUND)
    }

    @Test
    fun `expired challenge throws PASSKEY_CHALLENGE_EXPIRED`() {
        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge(any()) } throws
            BadRequestException("Expired", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)

        val ex = assertThrows<BadRequestException> { useCase.execute(command()) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }

    @Test
    fun `counter replay detected by webauthn4j throws PASSKEY_COUNTER_INVALID`() {
        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge(any()) } returns ByteArray(32)
        every { webAuthnManager.verify(any<AuthenticationRequest>(), any<AuthenticationParameters>()) } throws
            MaliciousCounterValueException("Counter replay")

        val ex = assertThrows<com.aibles.iam.shared.error.UnauthorizedException> { useCase.execute(command()) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }

    @Test
    fun `disabled user throws ForbiddenException without saving credential`() {
        val mockAuthData = mockk<AuthenticationData>(relaxed = true)
        every { mockAuthData.authenticatorData!!.signCount } returns 6L

        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge("sess") } returns ByteArray(32)
        every { webAuthnManager.verify(any<AuthenticationRequest>(), any<AuthenticationParameters>()) } returns mockAuthData
        // getUserUseCase returns a disabled user
        val disabledUser = User.create("disabled@test.com").also { it.disable() }
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns disabledUser

        assertThrows<com.aibles.iam.shared.error.ForbiddenException> { useCase.execute(command()) }

        // Credential must NOT have been saved
        verify(exactly = 0) { credentialRepository.save(any()) }
    }
}
