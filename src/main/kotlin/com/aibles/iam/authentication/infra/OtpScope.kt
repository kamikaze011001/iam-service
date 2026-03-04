package com.aibles.iam.authentication.infra

enum class OtpScope(val prefix: String) {
    PASSKEY_REG("otp:reg:"),
    SIGNUP("otp:signup:");
}
