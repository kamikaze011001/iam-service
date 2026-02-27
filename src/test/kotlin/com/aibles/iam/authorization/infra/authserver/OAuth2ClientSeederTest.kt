package com.aibles.iam.authorization.infra.authserver

import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.ApplicationArguments
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository

class OAuth2ClientSeederTest {

    private val repository = mockk<RegisteredClientRepository>(relaxed = true)
    private val properties = OAuth2ClientSeeder.Properties(
        iamWeb = OAuth2ClientSeeder.Properties.IamWebProperties(
            redirectUri = "http://localhost:3000/callback"
        ),
        iamService = OAuth2ClientSeeder.Properties.IamServiceProperties(
            clientSecret = "{noop}test-secret"
        ),
    )
    private val seeder = OAuth2ClientSeeder(repository, properties)

    @Test
    fun `seeds iam-web client when not present`() {
        every { repository.findByClientId("iam-web") } returns null
        every { repository.findByClientId("iam-service") } returns null

        seeder.run(mockk<ApplicationArguments>())

        val saved = mutableListOf<RegisteredClient>()
        verify { repository.save(capture(saved)) }

        val iamWeb = saved.find { it.clientId == "iam-web" }
        assertThat(iamWeb).isNotNull()
        assertThat(iamWeb!!.clientSettings.isRequireProofKey).isTrue()
        assertThat(iamWeb.scopes).contains("openid")
    }

    @Test
    fun `skips iam-web when already present`() {
        every { repository.findByClientId("iam-web") } returns mockk()
        every { repository.findByClientId("iam-service") } returns null

        seeder.run(mockk<ApplicationArguments>())

        verify(exactly = 0) { repository.save(match { it.clientId == "iam-web" }) }
        verify(exactly = 1) { repository.save(match { it.clientId == "iam-service" }) }
    }

    @Test
    fun `seeds iam-service with CLIENT_CREDENTIALS grant`() {
        every { repository.findByClientId(any()) } returns null

        seeder.run(mockk<ApplicationArguments>())

        verify {
            repository.save(match { client ->
                client.clientId == "iam-service" &&
                    client.authorizationGrantTypes.any { it.value == "client_credentials" }
            })
        }
    }
}
