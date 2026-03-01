-- V3: Composite index for filtered audit log queries.
-- The QueryAuditLogsUseCase filters by event_type and/or user_id
-- and always orders by created_at DESC. This composite index
-- covers the most common query patterns efficiently.
CREATE INDEX idx_audit_filtered ON audit_logs (event_type, user_id, created_at DESC);
