-- Chunked upload: one row per upload session, one row per received chunk.
-- The session row is the lease the client resumes against; chunk rows are what
-- "which parts are already here" is answered from.

CREATE TABLE upload_session (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id    BIGINT UNSIGNED NOT NULL,
    owner_id     BIGINT UNSIGNED NOT NULL,
    dir          VARCHAR(255)    NOT NULL DEFAULT '/',
    name         VARCHAR(255)    NOT NULL,
    size         BIGINT UNSIGNED NOT NULL,
    chunk_size   BIGINT UNSIGNED NOT NULL,
    chunk_count  INT UNSIGNED    NOT NULL,
    content_type VARCHAR(128)    NOT NULL DEFAULT 'application/octet-stream',
    created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_upload_session_tenant (tenant_id, id),
    KEY idx_upload_session_updated (updated_at),
    CONSTRAINT fk_upload_session_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE upload_chunk (
    upload_id  BIGINT UNSIGNED NOT NULL,
    -- 0-based, so chunk_count and the highest index always line up.
    idx        INT UNSIGNED    NOT NULL,
    size       BIGINT UNSIGNED NOT NULL,
    sha256     CHAR(64)        NOT NULL,
    created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (upload_id, idx),
    CONSTRAINT fk_upload_chunk_session FOREIGN KEY (upload_id) REFERENCES upload_session (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- An instant-upload hit appends a file row that points at an object another row
-- already owns, so one storage_key can back several rows. No reference counter
-- column is added on purpose: "does anyone else still use this key" is a single
-- indexed COUNT against idx_file_tenant_sha, and a denormalised counter would
-- only give it a way to drift.
