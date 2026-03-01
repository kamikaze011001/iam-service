package com.aibles.iam.audit.api

import com.aibles.iam.audit.api.dto.AuditLogResponse
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.shared.pagination.PageResponse
import com.aibles.iam.shared.response.ApiResponse
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

@RestController
@RequestMapping("/api/v1/audit-logs")
class AuditLogsController(
    private val queryAuditLogsUseCase: QueryAuditLogsUseCase,
) {

    @GetMapping
    fun getAuditLogs(
        @RequestParam(required = false) eventType: AuditEvent?,
        @RequestParam(required = false) userId: UUID?,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) from: Instant?,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) to: Instant?,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
    ): ApiResponse<PageResponse<AuditLogResponse>> {
        val result = queryAuditLogsUseCase.execute(
            QueryAuditLogsUseCase.Query(
                eventType = eventType,
                userId = userId,
                from = from,
                to = to,
                page = page,
                size = size,
            )
        )
        return ApiResponse.ok(
            PageResponse(
                content = result.content.map { AuditLogResponse.from(it) },
                page = result.page,
                size = result.size,
                totalElements = result.totalElements,
                totalPages = result.totalPages,
            )
        )
    }
}
