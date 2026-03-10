package com.aibles.iam.shared.web

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

class HttpContextExtractorTest {

    private val extractor = HttpContextExtractor()

    @AfterEach
    fun clearContext() = RequestContextHolder.resetRequestAttributes()

    private fun bindRequest(configure: MockHttpServletRequest.() -> Unit): MockHttpServletRequest {
        val req = MockHttpServletRequest().apply(configure)
        RequestContextHolder.setRequestAttributes(ServletRequestAttributes(req))
        return req
    }

    @Test
    fun `clientIp returns remoteAddr when no XFF header`() {
        bindRequest { remoteAddr = "192.168.1.1" }
        assert(extractor.clientIp() == "192.168.1.1")
    }

    @Test
    fun `clientIp returns first XFF IP`() {
        bindRequest {
            remoteAddr = "10.0.0.1"
            addHeader("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
        }
        assert(extractor.clientIp() == "203.0.113.5")
    }

    @Test
    fun `userAgent returns header value`() {
        bindRequest { addHeader("User-Agent", "Mozilla/5.0") }
        assert(extractor.userAgent() == "Mozilla/5.0")
    }

    @Test
    fun `clientIp returns null when no request context`() {
        // No RequestContextHolder bound — simulates background task or unit test
        assert(extractor.clientIp() == null)
    }

    @Test
    fun `userAgent returns null when no request context`() {
        assert(extractor.userAgent() == null)
    }
}
