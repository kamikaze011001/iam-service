package com.aibles.iam.authorization.infra.authserver

import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.stereotype.Component
import java.util.UUID

@Component
@EnableConfigurationProperties(OAuth2ClientSeeder.Properties::class)
class OAuth2ClientSeeder(
    private val registeredClientRepository: RegisteredClientRepository,
    private val properties: Properties,
) : ApplicationRunner {

    @ConfigurationProperties("oauth2.clients")
    data class Properties(
        val iamWeb: IamWebProperties = IamWebProperties(),
        val iamService: IamServiceProperties = IamServiceProperties(),
    ) {
        data class IamWebProperties(val redirectUri: String = "http://localhost:3000/callback")
        data class IamServiceProperties(val clientSecret: String = "{noop}changeme")
    }

    override fun run(args: ApplicationArguments) {
        seedIfAbsent(buildIamWebClient())
        seedIfAbsent(buildIamServiceClient())
    }

    private fun seedIfAbsent(client: RegisteredClient) {
        if (registeredClientRepository.findByClientId(client.clientId) == null) {
            registeredClientRepository.save(client)
        }
    }

    private fun buildIamWebClient() = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("iam-web")
        .clientName("IAM Web Application")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(properties.iamWeb.redirectUri)
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.EMAIL)
        .scope(OidcScopes.PROFILE)
        .clientSettings(ClientSettings.builder().requireProofKey(true).build())
        .build()

    private fun buildIamServiceClient() = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("iam-service")
        .clientName("IAM Service (machine-to-machine)")
        .clientSecret(properties.iamService.clientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("iam:read")
        .scope("iam:write")
        .build()
}
