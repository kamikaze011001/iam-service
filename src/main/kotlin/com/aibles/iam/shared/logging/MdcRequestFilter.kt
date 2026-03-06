package com.aibles.iam.shared.logging

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.util.UUID

@Component
@Order(1)
class MdcRequestFilter : OncePerRequestFilter() {

    public override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            MDC.put("requestId", UUID.randomUUID().toString().take(8))
            MDC.put("clientIp", resolveClientIp(request))
            MDC.put("userAgent", request.getHeader("User-Agent") ?: "unknown")
            filterChain.doFilter(request, response)
        } finally {
            MDC.clear()
        }
    }

    internal fun resolveClientIp(request: HttpServletRequest): String {
        val xff = request.getHeader("X-Forwarded-For")
        if (!xff.isNullOrBlank()) {
            return xff.split(",").first().trim()
        }
        return request.remoteAddr
    }
}
