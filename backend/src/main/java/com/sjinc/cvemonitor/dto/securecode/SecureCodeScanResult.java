package com.sjinc.cvemonitor.dto.securecode;

/**
 * 점검 1회 결과. failedFileCount가 0이 아니면 그 파일들은 "약점 없음"이 아니라 "못 봄"이라 화면이 따로 알린다.
 *
 * @param traceNote MyBatis ${} 연계 추적이 실패했거나 일부를 못 했을 때 화면 알림에 덧붙일 문구. 문제가 없으면 null
 */
public record SecureCodeScanResult(
        String systemName,
        int fileCount,
        int findingCount,
        int newCount,
        int resolvedCount,
        int failedFileCount,
        String traceNote
) {
}
