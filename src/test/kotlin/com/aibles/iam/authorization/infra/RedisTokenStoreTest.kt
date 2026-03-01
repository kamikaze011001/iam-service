package com.aibles.iam.authorization.infra

import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.containers.GenericContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.time.Duration
import java.util.UUID

@Testcontainers
class RedisTokenStoreTest {

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

    private val store: RedisTokenStore by lazy { RedisTokenStore(template) }

    @AfterEach
    fun flush() {
        template.connectionFactory?.connection?.serverCommands()?.flushAll()
    }

    @Test
    fun `store and consume returns correct userId`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.storeRefreshToken(token, userId, Duration.ofMinutes(30))

        val returned = store.validateAndConsume(token)
        assertThat(returned).isEqualTo(userId)
    }

    @Test
    fun `consuming same token twice throws UnauthorizedException`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.storeRefreshToken(token, userId, Duration.ofMinutes(30))

        store.validateAndConsume(token)  // first: success

        val ex = assertThrows<UnauthorizedException> {
            store.validateAndConsume(token)  // second: must fail
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
    }

    @Test
    fun `expired token throws UnauthorizedException`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.storeRefreshToken(token, userId, Duration.ofMillis(100))

        Thread.sleep(500)  // wait beyond TTL

        val ex = assertThrows<UnauthorizedException> {
            store.validateAndConsume(token)
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
    }

    @Test
    fun `revokeAllForUser removes all tokens for that user`() {
        val userId = UUID.randomUUID()
        val t1 = UUID.randomUUID().toString()
        val t2 = UUID.randomUUID().toString()
        store.storeRefreshToken(t1, userId, Duration.ofMinutes(30))
        store.storeRefreshToken(t2, userId, Duration.ofMinutes(30))

        store.revokeAllForUser(userId)

        val ex1 = assertThrows<UnauthorizedException> { store.validateAndConsume(t1) }
        assertThat(ex1.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
        val ex2 = assertThrows<UnauthorizedException> { store.validateAndConsume(t2) }
        assertThat(ex2.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
    }

    @Test
    fun `consumed token is removed from user set`() {
        val userId = UUID.randomUUID()
        val t1 = UUID.randomUUID().toString()
        val t2 = UUID.randomUUID().toString()
        store.storeRefreshToken(t1, userId, Duration.ofMinutes(30))
        store.storeRefreshToken(t2, userId, Duration.ofMinutes(30))

        store.validateAndConsume(t1)  // consume t1

        // t1 must no longer be in the user set
        val members = template.opsForSet().members("rt:u:$userId") ?: emptySet<String>()
        assertThat(members).doesNotContain(t1)
        assertThat(members).contains(t2)   // t2 still active
    }
}
