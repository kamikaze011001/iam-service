package com.aibles.iam.authentication.infra

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.containers.GenericContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.util.UUID

@Testcontainers
class RedisOtpStoreTest {

    companion object {
        @Container
        @JvmStatic
        val redis: GenericContainer<*> = GenericContainer("redis:7-alpine")
            .withExposedPorts(6379)
    }

    private val template: StringRedisTemplate by lazy {
        val factory = LettuceConnectionFactory("localhost", redis.getMappedPort(6379))
        factory.afterPropertiesSet()
        StringRedisTemplate(factory).apply { afterPropertiesSet() }
    }

    private val store: RedisOtpStore by lazy { RedisOtpStore(template) }

    @AfterEach
    fun flush() {
        template.connectionFactory?.connection?.serverCommands()?.flushAll()
    }

    // --- PASSKEY_REG scope (existing behavior, new signature) ---

    @Test
    fun `stores OTP and can retrieve it`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "123456")
        assertThat(store.getOtp(OtpScope.PASSKEY_REG, key)).isEqualTo("123456")
    }

    @Test
    fun `getOtp returns null after deletion`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "999999")
        store.deleteOtp(OtpScope.PASSKEY_REG, key)
        assertThat(store.getOtp(OtpScope.PASSKEY_REG, key)).isNull()
    }

    @Test
    fun `incrementAttempts returns current count`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "111111")
        assertThat(store.incrementAttempts(OtpScope.PASSKEY_REG, key)).isEqualTo(1L)
        assertThat(store.incrementAttempts(OtpScope.PASSKEY_REG, key)).isEqualTo(2L)
    }

    @Test
    fun `saveOtp resets attempt counter`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "111111")
        store.incrementAttempts(OtpScope.PASSKEY_REG, key)
        store.incrementAttempts(OtpScope.PASSKEY_REG, key)
        store.saveOtp(OtpScope.PASSKEY_REG, key, "222222")
        assertThat(store.incrementAttempts(OtpScope.PASSKEY_REG, key)).isEqualTo(1L)
    }

    @Test
    fun `saves and consumes otpToken`() {
        val token = UUID.randomUUID().toString()
        store.saveOtpToken(OtpScope.PASSKEY_REG, token, "some-value")
        assertThat(store.consumeOtpToken(OtpScope.PASSKEY_REG, token)).isEqualTo("some-value")
        assertThat(store.consumeOtpToken(OtpScope.PASSKEY_REG, token)).isNull()
    }

    @Test
    fun `incrementSendCount increments on each call`() {
        val key = UUID.randomUUID().toString()
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, key)).isEqualTo(1L)
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, key)).isEqualTo(2L)
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, key)).isEqualTo(3L)
    }

    @Test
    fun `incrementSendCount is independent per key`() {
        val keyA = UUID.randomUUID().toString()
        val keyB = UUID.randomUUID().toString()
        store.incrementSendCount(OtpScope.PASSKEY_REG, keyA)
        store.incrementSendCount(OtpScope.PASSKEY_REG, keyA)
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, keyB)).isEqualTo(1L)
    }

    // --- Cross-scope isolation ---

    @Test
    fun `different scopes are independent`() {
        val key = "shared-key@test.com"
        store.saveOtp(OtpScope.PASSKEY_REG, key, "111111")
        store.saveOtp(OtpScope.SIGNUP, key, "222222")
        assertThat(store.getOtp(OtpScope.PASSKEY_REG, key)).isEqualTo("111111")
        assertThat(store.getOtp(OtpScope.SIGNUP, key)).isEqualTo("222222")
    }

    @Test
    fun `signup scope token stores and consumes string value`() {
        val token = UUID.randomUUID().toString()
        store.saveOtpToken(OtpScope.SIGNUP, token, "user@test.com")
        assertThat(store.consumeOtpToken(OtpScope.SIGNUP, token)).isEqualTo("user@test.com")
        assertThat(store.consumeOtpToken(OtpScope.SIGNUP, token)).isNull()
    }
}
