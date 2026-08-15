-- Tenants, users and roles: the base every later stage scopes its queries against.

CREATE TABLE tenant (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name       VARCHAR(64)     NOT NULL,
    code       VARCHAR(32)     NOT NULL,
    created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tenant_code (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE `user` (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     BIGINT UNSIGNED NOT NULL,
    username      VARCHAR(64)     NOT NULL,
    password_hash VARCHAR(100)    NOT NULL,
    display_name  VARCHAR(64)     NOT NULL DEFAULT '',
    status        TINYINT         NOT NULL DEFAULT 1,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_tenant_username (tenant_id, username),
    KEY idx_user_tenant (tenant_id),
    CONSTRAINT fk_user_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE role (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id  BIGINT UNSIGNED NOT NULL,
    code       VARCHAR(32)     NOT NULL,
    name       VARCHAR(64)     NOT NULL,
    created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_tenant_code (tenant_id, code),
    CONSTRAINT fk_role_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE user_role (
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES `user` (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES role (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- Seed: two tenants, one admin each. Password for both is "passw0rd"
-- (bcrypt hash is stable, so the seed stays readable and reproducible).
INSERT INTO tenant (id, name, code)
VALUES (1, '华东业务部', 'east'),
       (2, '华南业务部', 'south');

INSERT INTO `user` (id, tenant_id, username, password_hash, display_name)
VALUES (1, 1, 'alice', '$2a$10$DeflL3mpnEEEcABJvoZMPeyjkrNNd.GIP/CqObNFw6aKhHI8FIinq', 'Alice'),
       (2, 2, 'bob', '$2a$10$DeflL3mpnEEEcABJvoZMPeyjkrNNd.GIP/CqObNFw6aKhHI8FIinq', 'Bob');

INSERT INTO role (id, tenant_id, code, name)
VALUES (1, 1, 'admin', '租户管理员'),
       (2, 2, 'admin', '租户管理员');

INSERT INTO user_role (user_id, role_id)
VALUES (1, 1),
       (2, 2);
