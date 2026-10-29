-- Audit trail for permission changes.
--
-- acl_entry and role_permission hold only the current state: who may do what
-- right now. They cannot answer "who granted this, and when", which is the first
-- question asked after an incident or a revocation dispute. This table is the
-- answer, one row per mutation.
--
-- Deliberately no foreign keys. An audit row must survive the deletion of the
-- actor, the role, or the tenant it refers to — a trail that the subject can
-- erase by being deleted is not a trail. actor_username is a snapshot for the
-- same reason: the user row may be gone before anyone reads this.
--
-- allow_mask / deny_mask / path describe ACL changes; detail carries whatever the
-- other actions need (the granted role id, the new permission set, whether a
-- revoke actually removed something). Keeping one wide table is the pragmatic
-- choice: a polymorphic event table with a JSON blob would push the parsing into
-- every reader.

CREATE TABLE permission_audit (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id      BIGINT UNSIGNED NOT NULL,
    -- Who made the change. Snapshot only; see the note above.
    actor_user_id  BIGINT UNSIGNED NOT NULL,
    actor_username VARCHAR(64)     NOT NULL,
    -- acl_set | acl_delete | role_create | role_delete | role_grant |
    -- role_revoke | role_permissions
    action         VARCHAR(32)     NOT NULL,
    subject_kind   VARCHAR(16)     NOT NULL DEFAULT '',
    subject_id     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    path           VARCHAR(255)    NOT NULL DEFAULT '',
    allow_mask     INT UNSIGNED    NOT NULL DEFAULT 0,
    deny_mask      INT UNSIGNED    NOT NULL DEFAULT 0,
    detail         VARCHAR(255)    NOT NULL DEFAULT '',
    created_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    -- Every read is "newest first for one tenant", so the index matches that.
    KEY idx_audit_tenant_id (tenant_id, id),
    KEY idx_audit_tenant_subject (tenant_id, subject_kind, subject_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
