package com.aibles.iam.authorization.infra.authserver

import com.aibles.iam.identity.domain.user.UserRepository
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component

@Component
class OidcTokenCustomizer(
    private val userRepository: UserRepository,
) : OAuth2TokenCustomizer<JwtEncodingContext> {

    override fun customize(context: JwtEncodingContext) {
        if (OidcParameterNames.ID_TOKEN != context.tokenType.value) return

        val googleSub = context.getPrincipal<Authentication>().name
        val user = userRepository.findByGoogleSub(googleSub) ?: return

        context.claims
            .claim("email", user.email)
            .claim("name", user.displayName ?: user.email)
            .claim("roles", user.roles.toList())
    }
}
