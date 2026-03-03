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

    @Test
    fun `stores OTP and can retrieve it`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "123456")
        assertThat(store.getOtp(userId)).isEqualTo("123456")
    }

    @Test
    fun `getOtp returns null after deletion`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "999999")
        store.deleteOtp(userId)
        assertThat(store.getOtp(userId)).isNull()
    }

    @Test
    fun `incrementAttempts returns current count`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "111111")
        assertThat(store.incrementAttempts(userId)).isEqualTo(1L)
        assertThat(store.incrementAttempts(userId)).isEqualTo(2L)
    }

    @Test
    fun `saveOtp resets attempt counter`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "111111")
        store.incrementAttempts(userId)
        store.incrementAttempts(userId)
        // resend resets attempts
        store.saveOtp(userId, "222222")
        assertThat(store.incrementAttempts(userId)).isEqualTo(1L)
    }

    @Test
    fun `saves and consumes otpToken`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.saveOtpToken(token, userId)
        assertThat(store.consumeOtpToken(token)).isEqualTo(userId)
        assertThat(store.consumeOtpToken(token)).isNull()  // one-time
    }

    @Test
    fun `incrementSendCount increments on each call`() {
        val userId = UUID.randomUUID()

        assertThat(store.incrementSendCount(userId)).isEqualTo(1L)
        assertThat(store.incrementSendCount(userId)).isEqualTo(2L)
        assertThat(store.incrementSendCount(userId)).isEqualTo(3L)
    }

    @Test
    fun `incrementSendCount is independent per user`() {
        val userA = UUID.randomUUID()
        val userB = UUID.randomUUID()

        store.incrementSendCount(userA)
        store.incrementSendCount(userA)

        assertThat(store.incrementSendCount(userB)).isEqualTo(1L)
    }
}
