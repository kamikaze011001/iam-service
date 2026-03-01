package com.aibles.iam.audit.domain.log

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import java.util.UUID

interface AuditLogRepository : JpaRepository<AuditLog, UUID>, JpaSpecificationExecutor<AuditLog>
