package com.aibles.iam.shared.ratelimit

import com.aibles.iam.shared.config.RateLimitProperties
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import jakarta.servlet.FilterChain
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

class RateLimitFilterTest {

    private val objectMapper: ObjectMapper = jacksonObjectMapper().registerModule(JavaTimeModule())

    @Test
    fun `allows requests under the limit`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = true, requestsPerMinute = 5), objectMapper)
        val chain = FilterChain { _, _ -> }

        repeat(5) {
            val request = MockHttpServletRequest()
            val response = MockHttpServletResponse()
            filter.doFilter(request, response, chain)
            assertThat(response.status).isNotEqualTo(429)
        }
    }

    @Test
    fun `returns 429 when limit exceeded`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = true, requestsPerMinute = 2), objectMapper)
        val chain = FilterChain { _, _ -> }

        // Consume both tokens
        repeat(2) {
            filter.doFilter(MockHttpServletRequest(), MockHttpServletResponse(), chain)
        }

        // Third request should be rejected
        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()
        filter.doFilter(request, response, chain)

        assertThat(response.status).isEqualTo(429)
        assertThat(response.contentType).isEqualTo("application/json")
        assertThat(response.contentAsString).contains("RATE_LIMIT_EXCEEDED")
        assertThat(response.getHeader("Retry-After")).isEqualTo("60")
    }

    @Test
    fun `disabled filter passes all requests through`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = false, requestsPerMinute = 1), objectMapper)
        val chain = FilterChain { _, _ -> }

        repeat(10) {
            val request = MockHttpServletRequest()
            val response = MockHttpServletResponse()
            filter.doFilter(request, response, chain)
            assertThat(response.status).isNotEqualTo(429)
        }
    }

    @Test
    fun `uses X-Forwarded-For header when present`() {
        // The test's MockHttpServletRequest has remoteAddr "127.0.0.1" by default
        val filter = RateLimitFilter(RateLimitProperties(enabled = true, requestsPerMinute = 1, trustedProxies = listOf("127.0.0.1")), objectMapper)
        val chain = FilterChain { _, _ -> }

        val req1 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "1.2.3.4") }
        filter.doFilter(req1, MockHttpServletResponse(), chain)

        val req2 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "5.6.7.8") }
        val resp2 = MockHttpServletResponse()
        filter.doFilter(req2, resp2, chain)
        assertThat(resp2.status).isNotEqualTo(429)

        val req3 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "1.2.3.4") }
        val resp3 = MockHttpServletResponse()
        filter.doFilter(req3, resp3, chain)
        assertThat(resp3.status).isEqualTo(429)
    }

    @Test
    fun `X-Forwarded-For is ignored when remoteAddr is not a trusted proxy`() {
        // Limit = 1 request. If XFF were trusted, "spoofed-ip" would get its own bucket.
        // Since remoteAddr "127.0.0.1" is not in trusted proxies, XFF is ignored and
        // both requests share the same bucket (keyed on "127.0.0.1"), so the 2nd is rejected.
        val props = RateLimitProperties(enabled = true, requestsPerMinute = 1, trustedProxies = emptyList())
        val filter = RateLimitFilter(props, objectMapper)
        val chain = FilterChain { _, _ -> }

        val req1 = MockHttpServletRequest().apply {
            remoteAddr = "127.0.0.1"
            addHeader("X-Forwarded-For", "spoofed-ip")
        }
        filter.doFilter(req1, MockHttpServletResponse(), chain)

        val req2 = MockHttpServletRequest().apply {
            remoteAddr = "127.0.0.1"
            addHeader("X-Forwarded-For", "spoofed-ip")
        }
        val resp2 = MockHttpServletResponse()
        filter.doFilter(req2, resp2, chain)

        assertThat(resp2.status).isEqualTo(429)
    }

    @Test
    fun `X-Forwarded-For is used when remoteAddr is a trusted proxy`() {
        val props = RateLimitProperties(enabled = true, requestsPerMinute = 1, trustedProxies = listOf("10.0.0.1"))
        val filter = RateLimitFilter(props, objectMapper)
        val chain = FilterChain { _, _ -> }

        // Request from trusted proxy 10.0.0.1 with client IP 1.2.3.4
        val req1 = MockHttpServletRequest().apply {
            remoteAddr = "10.0.0.1"
            addHeader("X-Forwarded-For", "1.2.3.4")
        }
        filter.doFilter(req1, MockHttpServletResponse(), chain)

        // Different client IP 5.6.7.8 from same proxy — gets its own bucket, not throttled
        val req2 = MockHttpServletRequest().apply {
            remoteAddr = "10.0.0.1"
            addHeader("X-Forwarded-For", "5.6.7.8")
        }
        val resp2 = MockHttpServletResponse()
        filter.doFilter(req2, resp2, chain)

        assertThat(resp2.status).isNotEqualTo(429)
    }
}
