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
 * ddl-auto=update가 하지 않는 스키마 변경(기존 컬럼의 NOT NULL 해제 등)을 기동 때 한 번 한다. 하지 않으면 기존 파일 DB에
 * 제약이 남아 insert가 실패한다. 적용 여부는 INFORMATION_SCHEMA로 확인하고, DataInitializer보다 먼저 돈다(SQL은 H2 문법).
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

    /** (테이블, 컬럼) — 기능을 없애 더는 쓰지 않는 컬럼(영향 분석 신뢰도, 우리 코드 대조용 소스 사용 목록). */
    private static final List<String[]> DROPPED_COLUMNS = List.of(
            new String[]{"UPGRADE_IMPACTS", "CONFIDENCE"},
            new String[]{"SCAN_SNAPSHOT", "SOURCE_USAGE_JSON"});

    @Override
    public void run(String... args) {
        for (String[] column : NULLABLE_COLUMNS) {
            dropNotNull(column[0], column[1]);
        }
        for (String[] column : DROPPED_COLUMNS) {
            dropColumn(column[0], column[1]);
        }
    }

    private void dropColumn(String table, String column) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = ?",
                Integer.class, table, column);
        if (count == null || count == 0) {
            return;
        }
        // 테이블·컬럼 이름은 위 상수에서만 온다(사용자 입력 아님).
        jdbc.execute("ALTER TABLE " + table + " DROP COLUMN " + column);
        log.info("스키마 변경: 쓰지 않는 컬럼 {}.{}를 지웠습니다.", table, column);
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
