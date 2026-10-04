-- RBAC + ACL.
--
-- Two layers that answer different questions:
--   role_permission  — 这个角色能不能做这类事（粗粒度能力）
--   acl_entry        — 这条目录/文件归谁管（细粒度资源归属，沿目录树继承）
-- A request is allowed when its roles grant the action AND the ACL does not deny
-- it on the target path. Deny wins over inherit, which is what makes "子目录显式
-- 拒绝覆盖继承" expressible.

CREATE TABLE permission (
    code        VARCHAR(64) NOT NULL,
    description VARCHAR(128) NOT NULL DEFAULT '',
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE role_permission (
    tenant_id  BIGINT UNSIGNED NOT NULL,
    role_id    BIGINT UNSIGNED NOT NULL,
    permission VARCHAR(64)     NOT NULL,
    PRIMARY KEY (role_id, permission),
    KEY idx_role_permission_tenant (tenant_id),
    CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES role (id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_perm FOREIGN KEY (permission) REFERENCES permission (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- One row per (subject, path). subject is either a user or a role; the kind
-- column says which, so a single lookup covers both without a second table.
CREATE TABLE acl_entry (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id  BIGINT UNSIGNED NOT NULL,
    subject_kind ENUM ('user', 'role') NOT NULL,
    subject_id BIGINT UNSIGNED NOT NULL,
    -- Normalised like file.dir: always starts with "/", no trailing slash.
    path       VARCHAR(255)    NOT NULL,
    -- Bitmask of the actions granted (or denied) on this path: 1 read, 2 write, 4 delete.
    allow_mask INT UNSIGNED    NOT NULL DEFAULT 0,
    deny_mask  INT UNSIGNED    NOT NULL DEFAULT 0,
    -- Depth lets the resolver sort candidates nearest-first without parsing paths.
    depth      INT UNSIGNED    NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_acl_subject_path (tenant_id, subject_kind, subject_id, path),
    KEY idx_acl_lookup (tenant_id, subject_kind, subject_id, depth),
    CONSTRAINT fk_acl_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT INTO permission (code, description)
VALUES ('file.read', '查看与下载文件'),
       ('file.write', '上传与修改文件'),
       ('file.delete', '删除文件'),
       ('perm.manage', '管理权限');

-- admin gets every permission code within its own tenant. There is no second
-- role yet, so the matrix currently has one role per tenant.
INSERT INTO role_permission (tenant_id, role_id, permission)
VALUES (1, 1, 'file.read'), (1, 1, 'file.write'), (1, 1, 'file.delete'), (1, 1, 'perm.manage'),
       (2, 2, 'file.read'), (2, 2, 'file.write'), (2, 2, 'file.delete'), (2, 2, 'perm.manage');

-- Root grant: every admin can read/write/delete under "/" in its tenant.
INSERT INTO acl_entry (tenant_id, subject_kind, subject_id, path, allow_mask, deny_mask, depth)
VALUES (1, 'role', 1, '/', 7, 0, 0),
       (2, 'role', 2, '/', 7, 0, 0);
