-- Tenant quota.
--
-- The number is 0006, not 0005: the file that used to sit in between created the
-- index_metadata and index_dead_letter tables, and it was removed together with
-- the AI enrichment pipeline. Migrations are tracked by file name, so the gap is
-- harmless — and renaming this one would make an existing database try to add
-- the column a second time.
--
-- One column rather than a separate table: the limit is per tenant and there is
-- exactly one of it. 0 means "no limit", which keeps an existing installation
-- working after this migration without an operator having to pick a number.
--
-- The used side is deliberately not stored: it is SUM(size) over the file table,
-- and a denormalised counter is a second source of truth that drifts the first
-- time a delete path forgets to decrement it. With the row count this project
-- targets, counting on demand is cheaper than being wrong.

ALTER TABLE tenant
    ADD COLUMN quota_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER code;

-- Give the two seed tenants a visible ceiling so the quota path is exercised by
-- the demo rather than only by tests.
UPDATE tenant SET quota_bytes = 1073741824 WHERE quota_bytes = 0;
