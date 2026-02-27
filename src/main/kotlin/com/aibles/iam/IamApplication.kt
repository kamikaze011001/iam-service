package com.aibles.iam

import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.config.WebAuthnProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(JwtProperties::class, WebAuthnProperties::class)
class IamApplication

fun main(args: Array<String>) {
    runApplication<IamApplication>(*args)
}
