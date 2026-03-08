package com.aibles.iam.shared.web

import org.springframework.stereotype.Component
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

/**
 * Reads HTTP request metadata from the current request context.
 * Works anywhere in the call stack during a request (controllers, use cases, handlers).
 * Returns null when called outside of a request context (e.g., background tasks, tests).
 */
@Component
class HttpContextExtractor {

    fun clientIp(): String? {
        val request = currentRequest() ?: return null
        val xff = request.getHeader("X-Forwarded-For")
        if (!xff.isNullOrBlank()) return xff.split(",").first().trim()
        return request.remoteAddr
    }

    fun userAgent(): String? = currentRequest()?.getHeader("User-Agent")

    private fun currentRequest() =
        (RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes)?.request
}
