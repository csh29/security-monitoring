package com.sjinc.securitymonitor.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * ddl-auto=update가 하지 않는 스키마 변경을 기동 때 한 번 한다. update는 컬럼·테이블을 추가만 하고 기존 컬럼의 NOT NULL을 풀지 않는다 —
 * 엔티티에서 nullable을 바꿔도 이미 만들어진 DB(파일 DB라 재기동해도 남는다)에는 제약이 그대로 남아 insert가 실패한다.
 * 이미 적용된 변경은 다시 하지 않는다(INFORMATION_SCHEMA로 확인). 다른 초기화(DataInitializer)보다 먼저 돈다.
 *
 * <p>SQL은 H2 문법이다(이 시스템의 DB). DB를 바꾸면 여기를 그 DB 문법으로 고친다.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class SchemaMigration implements CommandLineRunner {

    private final JdbcTemplate jdbc;

    /** (테이블, 컬럼) — 업로드 소스 앱(App.SOURCE_UPLOAD)은 저장소 URL·브랜치가 없다. 점검 이력도 앱 값을 복사하므로 같이 푼다. */
    private static final List<String[]> NULLABLE_COLUMNS = List.of(
            new String[]{"APPS", "REPO_URL"},
            new String[]{"APPS", "BRANCH"},
            new String[]{"SECURE_CODE_SCANS", "REPO_URL"},
            new String[]{"SECURE_CODE_SCANS", "BRANCH"});

    @Override
    public void run(String... args) {
        for (String[] column : NULLABLE_COLUMNS) {
            dropNotNull(column[0], column[1]);
        }
    }

    private void dropNotNull(String table, String column) {
        List<String> nullable = jdbc.queryForList(
                "SELECT IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = ?",
                String.class, table, column);
        if (nullable.isEmpty() || "YES".equals(nullable.get(0))) {
            return;
        }
        // 테이블·컬럼 이름은 위 상수에서만 온다(사용자 입력 아님).
        jdbc.execute("ALTER TABLE " + table + " ALTER COLUMN " + column + " SET NULL");
        log.info("스키마 변경: {}.{}의 NOT NULL을 풀었습니다.", table, column);
    }
}
