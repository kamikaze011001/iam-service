package com.aibles.iam.identity.domain.user

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class UserTest {

    @Test
    fun `create lowercases and trims email`() =
        assertThat(User.create("  TEST@EXAMPLE.COM  ").email).isEqualTo("test@example.com")

    @Test
    fun `create rejects blank email`() =
        assertThrows<IllegalArgumentException> { User.create("") }

    @Test
    fun `create rejects email without at sign`() =
        assertThrows<IllegalArgumentException> { User.create("notanemail") }

    @Test
    fun `disable sets DISABLED status`() {
        val user = User.create("a@b.com").also { it.disable() }
        assertThat(user.isActive()).isFalse()
        assertThat(user.status).isEqualTo(UserStatus.DISABLED)
    }

    @Test
    fun `enable restores ACTIVE after disable`() {
        val user = User.create("a@b.com").also { it.disable(); it.enable() }
        assertThat(user.isActive()).isTrue()
    }

    @Test
    fun `updateProfile trims display name`() {
        val user = User.create("a@b.com").also { it.updateProfile("  Alice  ") }
        assertThat(user.displayName).isEqualTo("Alice")
    }

    @Test
    fun `recordLogin sets lastLoginAt`() {
        val user = User.create("a@b.com").also { it.recordLogin() }
        assertThat(user.lastLoginAt).isNotNull()
    }
}
