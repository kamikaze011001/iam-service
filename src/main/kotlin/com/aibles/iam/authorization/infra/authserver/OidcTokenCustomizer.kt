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

        // Principal name carries the Google sub claim when authenticated via Google OAuth2 (OidcUser).
        // For future non-Google AS flows (e.g. Passkey), this lookup will return null and
        // ID token enrichment will be silently skipped — revisit when non-Google AS flows are added.
        val googleSub = context.getPrincipal<Authentication>().name
        val user = userRepository.findByGoogleSub(googleSub) ?: return

        context.claims
            .claim("email", user.email)
            .claim("name", user.displayName ?: user.email)  // Override standard OIDC name claim with stored display name
            .claim("roles", user.roles.toList())
    }
}
