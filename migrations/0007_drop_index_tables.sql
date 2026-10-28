-- Drop the tables that belonged to the AI enrichment pipeline.
--
-- 0005_index.sql created index_metadata and index_dead_letter; that file is gone
-- together with the pipeline, but an existing database still has the tables and
-- still has a schema_migrations row naming the removed file. Neither is
-- referenced by any code any more, so they are pure residue: rows nobody reads,
-- in tables nobody writes, that make `SHOW TABLES` lie about what the service
-- does.
--
-- This migration is the cleanup, and it is deliberately written to be safe on a
-- database that never had the tables (a fresh install): DROP TABLE IF EXISTS
-- makes it a no-op there, and deleting the stale schema_migrations row is a
-- DELETE of a value that simply is not present.
--
-- The order matters only for readability: both tables reference file(id) with ON
-- DELETE CASCADE, so dropping either first is fine.

DROP TABLE IF EXISTS index_dead_letter;
DROP TABLE IF EXISTS index_metadata;

-- Forget that 0005_index.sql ever ran. Leaving the row would make the applied
-- set claim a migration whose file no longer exists, which turns a harmless gap
-- into a confusing one for anyone comparing schema_migrations against the
-- migrations directory.
DELETE FROM schema_migrations WHERE version = '0005_index.sql';
