package com.aibles.iam.shared.logging

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.junit.jupiter.api.Test
import org.slf4j.MDC

class MdcRequestFilterTest {

    private val filter = MdcRequestFilter()
    private val request = mockk<HttpServletRequest>(relaxed = true)
    private val response = mockk<HttpServletResponse>(relaxed = true)
    private val chain = mockk<FilterChain>(relaxed = true)

    @Test
    fun `sets requestId in MDC and clears after request`() {
        every { request.remoteAddr } returns "127.0.0.1"
        every { request.getHeader("X-Forwarded-For") } returns null
        every { request.getHeader("User-Agent") } returns "TestAgent/1.0"

        filter.doFilterInternal(request, response, chain)

        // MDC must be cleared after request completes
        assert(MDC.get("requestId") == null)
        verify { chain.doFilter(request, response) }
    }

    @Test
    fun `uses X-Forwarded-For IP when present`() {
        every { request.remoteAddr } returns "10.0.0.1"
        every { request.getHeader("X-Forwarded-For") } returns "203.0.113.5, 10.0.0.1"
        every { request.getHeader("User-Agent") } returns null

        var capturedIp: String? = null
        every { chain.doFilter(any(), any()) } answers {
            capturedIp = MDC.get("clientIp")
        }

        filter.doFilterInternal(request, response, chain)

        assert(capturedIp == "203.0.113.5") { "Expected first XFF IP, got $capturedIp" }
    }

    @Test
    fun `clears MDC even when filterChain throws`() {
        every { request.remoteAddr } returns "127.0.0.1"
        every { request.getHeader(any()) } returns null
        every { chain.doFilter(any(), any()) } throws RuntimeException("boom")

        try {
            filter.doFilterInternal(request, response, chain)
        } catch (_: RuntimeException) {}

        assert(MDC.get("requestId") == null) { "MDC must be cleared even after exception" }
    }
}
