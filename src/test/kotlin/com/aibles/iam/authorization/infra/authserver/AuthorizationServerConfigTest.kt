package com.aibles.iam.authorization.infra.authserver

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.security.KeyPairGenerator
import java.util.Base64

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthorizationServerConfigTest {

    @Autowired lateinit var mockMvc: MockMvc

    companion object {
        @Container @JvmStatic
        val postgres: PostgreSQLContainer<*> = PostgreSQLContainer("postgres:16-alpine")

        @Container @JvmStatic
        val redis: GenericContainer<*> = GenericContainer("redis:7-alpine").withExposedPorts(6379)

        private val keyPair by lazy {
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }

        @JvmStatic
        @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url") { postgres.jdbcUrl }
            registry.add("spring.datasource.username") { postgres.username }
            registry.add("spring.datasource.password") { postgres.password }
            registry.add("spring.data.redis.host") { redis.host }
            registry.add("spring.data.redis.port") { redis.getMappedPort(6379).toString() }
            registry.add("jwt.private-key") { Base64.getEncoder().encodeToString(keyPair.private.encoded) }
            registry.add("jwt.public-key") { Base64.getEncoder().encodeToString(keyPair.public.encoded) }
        }
    }

    @Test
    fun `OIDC discovery endpoint returns issuer and jwks_uri`() {
        mockMvc.get("/.well-known/openid-configuration")
            .andExpect {
                status { isOk() }
                jsonPath("$.issuer") { exists() }
                jsonPath("$.jwks_uri") { exists() }
                jsonPath("$.token_endpoint") { exists() }
                jsonPath("$.authorization_endpoint") { exists() }
            }
    }

    @Test
    fun `JWK Set endpoint returns RSA key`() {
        mockMvc.get("/oauth2/jwks")
            .andExpect {
                status { isOk() }
                jsonPath("$.keys") { isArray() }
                jsonPath("$.keys[0].kty") { value("RSA") }
                jsonPath("$.keys[0].kid") { value("iam-rsa") }
            }
    }
}
