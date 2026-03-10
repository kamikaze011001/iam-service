package com.aibles.iam.identity.infra

import com.aibles.iam.identity.domain.user.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.stereotype.Component

@Component
class AdminBootstrapRunner(
    private val userRepository: UserRepository,
    @Value("\${app.bootstrap.admin-email:}") private val adminEmail: String,
) : ApplicationRunner {

    private val logger = LoggerFactory.getLogger(javaClass)

    override fun run(args: ApplicationArguments) {
        if (adminEmail.isBlank()) return

        val user = userRepository.findByEmail(adminEmail)
        if (user == null) {
            logger.warn("Bootstrap: admin user '{}' not found — register them first", adminEmail)
            return
        }
        if (user.roles.contains("ADMIN")) {
            logger.info("Bootstrap: '{}' already has ADMIN role", adminEmail)
            return
        }
        user.grantRole("ADMIN")
        userRepository.save(user)
        logger.info("Bootstrap: promoted '{}' to ADMIN", adminEmail)
    }
}
