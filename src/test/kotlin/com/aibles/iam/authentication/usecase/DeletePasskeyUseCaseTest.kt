package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class DeletePasskeyUseCaseTest {

    private val credentialRepository = mockk<PasskeyCredentialRepository>()
    private val useCase = DeletePasskeyUseCase(credentialRepository)

    private val userId = UUID.randomUUID()
    private val credentialId = UUID.randomUUID()

    @Test
    fun `happy path deletes existing credential`() {
        val credential = PasskeyCredential(
            id = credentialId, userId = userId,
            credentialId = byteArrayOf(1, 2), publicKeyCose = byteArrayOf(3, 4),
        )
        every { credentialRepository.findById(credentialId) } returns java.util.Optional.of(credential)
        every { credentialRepository.delete(credential) } just runs

        useCase.execute(DeletePasskeyUseCase.Command(userId, credentialId))

        verify(exactly = 1) { credentialRepository.delete(credential) }
    }

    @Test
    fun `unknown credential throws PASSKEY_NOT_FOUND`() {
        every { credentialRepository.findById(credentialId) } returns java.util.Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(DeletePasskeyUseCase.Command(userId, credentialId))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_NOT_FOUND)
    }

    @Test
    fun `credential belonging to different user throws PASSKEY_NOT_FOUND`() {
        val otherUser = UUID.randomUUID()
        val credential = PasskeyCredential(
            id = credentialId, userId = otherUser,
            credentialId = byteArrayOf(1, 2), publicKeyCose = byteArrayOf(3, 4),
        )
        every { credentialRepository.findById(credentialId) } returns java.util.Optional.of(credential)

        val ex = assertThrows<NotFoundException> {
            useCase.execute(DeletePasskeyUseCase.Command(userId, credentialId))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_NOT_FOUND)
    }
}
