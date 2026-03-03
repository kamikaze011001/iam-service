package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.config.MailProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.stereotype.Component

@Component
@EnableConfigurationProperties(MailProperties::class)
class EmailService(
    private val mailSender: JavaMailSender,
    private val mailProperties: MailProperties,
) {
    fun sendOtp(toEmail: String, otpCode: String) {
        val message = mailSender.createMimeMessage()
        val helper = MimeMessageHelper(message, false, "UTF-8")
        helper.setFrom("${mailProperties.fromName} <${mailProperties.from}>")
        helper.setTo(toEmail)
        helper.setSubject("Your passkey registration code")
        helper.setText(
            """
            Your one-time verification code is:

                $otpCode

            This code expires in 5 minutes. Do not share it with anyone.
            """.trimIndent()
        )
        mailSender.send(message)
    }
}
