package com.sjinc.securitymonitor.config;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import static org.assertj.core.api.Assertions.assertThat;

class SchemaMigrationTest {

    @Test
    void 기존_DB의_NOT_NULL을_풀고_다시_돌려도_문제없다() {
        // 이 컬럼들이 NOT NULL로 만들어져 있던 기존 파일 DB를 흉내 낸다(ddl-auto=update는 제약을 풀지 않는다).
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:migration;DB_CLOSE_DELAY=-1", "sa", ""));
        jdbc.execute("CREATE TABLE apps (app_id BIGINT PRIMARY KEY, repo_url VARCHAR(255) NOT NULL, branch VARCHAR(255) NOT NULL)");
        jdbc.execute("CREATE TABLE secure_code_scans (secure_code_scan_id BIGINT PRIMARY KEY, repo_url VARCHAR(255) NOT NULL, branch VARCHAR(255) NOT NULL)");
        SchemaMigration migration = new SchemaMigration(jdbc);

        migration.run();
        migration.run(); // 이미 풀린 컬럼은 건너뛴다

        jdbc.update("INSERT INTO apps (app_id, repo_url, branch) VALUES (1, NULL, NULL)");
        jdbc.update("INSERT INTO secure_code_scans (secure_code_scan_id, repo_url, branch) VALUES (1, NULL, NULL)");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM apps WHERE repo_url IS NULL", Integer.class)).isEqualTo(1);
    }
}
