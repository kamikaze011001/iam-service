package com.aibles.iam.authentication.domain.passkey

import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class PasskeyCredentialTest {

    private fun credential(counter: Long = 0) = PasskeyCredential(
        userId = UUID.randomUUID(),
        credentialId = byteArrayOf(1, 2, 3),
        publicKeyCose = byteArrayOf(4, 5, 6),
        signCounter = counter,
    )

    @Test
    fun `verifyAndIncrementCounter accepts higher counter`() {
        val c = credential(5)
        c.verifyAndIncrementCounter(6)
        assertThat(c.signCounter).isEqualTo(6)
    }

    @Test
    fun `verifyAndIncrementCounter rejects equal counter (replay)`() {
        val ex = assertThrows<UnauthorizedException> { credential(5).verifyAndIncrementCounter(5) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }

    @Test
    fun `verifyAndIncrementCounter rejects lower counter (replay)`() {
        val ex = assertThrows<UnauthorizedException> { credential(5).verifyAndIncrementCounter(3) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }

    @Test
    fun `verifyAndIncrementCounter allows zero counter when stored counter is also zero (spec compliance)`() {
        val c = credential(0)
        c.verifyAndIncrementCounter(0L)   // authenticator doesn't support counters — must not throw
        assertThat(c.signCounter).isEqualTo(0L)
    }
}
