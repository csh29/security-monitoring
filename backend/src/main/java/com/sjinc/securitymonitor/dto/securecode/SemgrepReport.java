package com.sjinc.securitymonitor.dto.securecode;

import java.util.List;
import java.util.Set;

/**
 * Semgrep 실행 결과(JSON) 해석본.
 *
 * @param failedFiles      해석 실패·시간 초과 등으로 끝까지 못 본 파일(저장소 루트 기준, 구분자 /)
 * @param scannedFileCount Semgrep이 읽은 파일 수
 */
public record SemgrepReport(
        List<SemgrepMatch> matches,
        Set<String> failedFiles,
        int scannedFileCount,
        String engineVersion
) {
}
