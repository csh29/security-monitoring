package com.sjinc.cvemonitor.dto.securecode;

import com.sjinc.cvemonitor.dto.vulnerability.AppVulnerabilityCount;

import java.util.List;

/**
 * 홈 대시보드의 시큐어코딩 구역. 라이브러리 취약점 KPI와 나란히 보이도록 같은 모양(건수·비율 2개 + 앱별 TOP N)으로 맞췄다.
 *
 * @param openCount   미조치(OPEN) 건수
 * @param openHighRate 미조치 중 HIGH 비율(%) — 라이브러리 쪽 "미해결 크리티컬 비율"에 해당한다(코드 점검 심각도에는 CRITICAL이 없다)
 * @param handledRate 전체 탐지 중 사람이·스캔이 처리한(조치완료·오탐·위험수용) 비율(%)
 * @param scanned     점검을 한 번이라도 해서 탐지 이력이 있는가 — 없으면 화면이 0%/100% 대신 "점검 전"으로 보인다
 * @param topApps     앱별 미조치 건수, 많은 순(앱별 막대의 단위는 라이브러리 쪽과 같은 AppVulnerabilityCount)
 */
public record SecureCodeDashboard(
        long openCount,
        long openHighRate,
        long handledRate,
        boolean scanned,
        List<AppVulnerabilityCount> topApps
) {
}
