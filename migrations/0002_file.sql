-- File metadata. Bytes live in the storage backend; this table is the index the
-- API lists and authorizes against, so tenant_id is part of every index.

CREATE TABLE file (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id    BIGINT UNSIGNED NOT NULL,
    owner_id     BIGINT UNSIGNED NOT NULL,
    -- dir is capped at 255 so the (tenant, dir, name) unique key stays under
    -- InnoDB's 3072-byte limit at utf8mb4 (8 + 4*255 + 4*255 = 2048).
    dir          VARCHAR(255)    NOT NULL DEFAULT '/',
    name         VARCHAR(255)    NOT NULL,
    size         BIGINT UNSIGNED NOT NULL,
    sha256       CHAR(64)        NOT NULL,
    content_type VARCHAR(128)    NOT NULL DEFAULT 'application/octet-stream',
    storage      VARCHAR(16)     NOT NULL DEFAULT 'local',
    storage_key  VARCHAR(512)    NOT NULL,
    created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_file_tenant_dir_name (tenant_id, dir, name),
    KEY idx_file_tenant_dir (tenant_id, dir),
    KEY idx_file_tenant_sha (tenant_id, sha256),
    CONSTRAINT fk_file_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
