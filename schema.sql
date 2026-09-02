CREATE TABLE IF NOT EXISTS spark_repo_claims (
    github_id   BIGINT UNSIGNED NOT NULL,
    phase       VARCHAR(16) CHARACTER SET ascii NOT NULL,
    github_login VARCHAR(39) CHARACTER SET ascii NOT NULL,
    repo_name   VARCHAR(100) CHARACTER SET ascii NOT NULL,
    repo_id     BIGINT UNSIGNED NULL,
    repo_url    VARCHAR(255) CHARACTER SET ascii NOT NULL DEFAULT '',
    invitation_url VARCHAR(255) CHARACTER SET ascii NOT NULL DEFAULT '',
    created_at  BIGINT UNSIGNED NOT NULL,
    completed_at BIGINT UNSIGNED NULL,
    PRIMARY KEY (github_id, phase),
    UNIQUE KEY spark_repo_claims_repo_name (repo_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
