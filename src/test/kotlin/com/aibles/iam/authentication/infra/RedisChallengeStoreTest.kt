package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.containers.GenericContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.util.UUID

@Testcontainers
class RedisChallengeStoreTest {

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

    private val store: RedisChallengeStore by lazy { RedisChallengeStore(template) }

    @AfterEach
    fun flush() {
        template.connectionFactory?.connection?.serverCommands()?.flushAll()
    }

    @Test
    fun `store and retrieve challenge succeeds once`() {
        val sessionId = UUID.randomUUID().toString()
        val challenge = "hello-challenge".toByteArray()

        store.storeChallenge(sessionId, challenge)
        val returned = store.getAndDeleteChallenge(sessionId)

        assertThat(returned).isEqualTo(challenge)
    }

    @Test
    fun `retrieving challenge twice throws BadRequestException with PASSKEY_CHALLENGE_EXPIRED`() {
        val sessionId = UUID.randomUUID().toString()
        store.storeChallenge(sessionId, "challenge".toByteArray())

        store.getAndDeleteChallenge(sessionId)  // first retrieval succeeds

        val ex = assertThrows<BadRequestException> {
            store.getAndDeleteChallenge(sessionId)  // second: must fail
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }

    @Test
    fun `getting non-existent challenge throws BadRequestException with PASSKEY_CHALLENGE_EXPIRED`() {
        val ex = assertThrows<BadRequestException> {
            store.getAndDeleteChallenge("no-such-session")
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }
}
