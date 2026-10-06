package com.sjinc.securitymonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;


/**
 * 개별 CVE(취약점) 정보를 담는 핵심 도메인 DTO.
 *
 * <p>NVD 응답의 {@code vulnerabilities[].cve} 경로에 해당하며,
 * 실제로는 이보다 훨씬 많은 필드(references, configurations, weaknesses 등)가
 * 내려오지만 현재 시스템에서 필요한 필드만 선별해서 매핑한다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CveItem {

    /** CVE 고유 식별자. 예: "CVE-2024-12345" */
    private String id;

    /** NVD 측에서 이 CVE 정보를 마지막으로 수정한 시각 (ISO-8601 문자열). 증분 동기화 시 기준값으로 사용. */
    private String lastModified;

    /** 다국어 취약점 설명 목록. 보통 영어(en)만 사용하므로 {@link #getSummary()}에서 en 항목만 골라 쓴다. */
    private List<Description> descriptions;

    /** CVSS 등 취약점 심각도 점수 정보. 버전에 따라 v2/v3/v3.1 metric이 섞여 내려올 수 있다. */
    private Metrics metrics;

    /**
     * NVD가 구조화된 형태로 내려주는 실제 영향 버전 범위(CPE 매치). 이전엔 이 필드가 없어서
     * Jackson이 조용히 버렸고, AI가 description 프로즈만 보고 영향 범위를 추측해야 했다 —
     * 그 결과 설명에 영향 범위가 여러 줄 나올 때 일부를 놓치는 실수가 실제로 있었다.
     * 이제 이 필드로 설치 버전이 실제 영향 범위 안에 있는지 자바가 직접 계산한다.
     */
    private List<NvdConfiguration> configurations;


    /**
     * descriptions 중 언어가 "en"인 설명 하나를 찾아 반환한다.
     * 일치하는 항목이 없으면 빈 문자열을 반환한다(설명 없음으로 처리).
     */
    public String getSummary() {
        return descriptions.stream()
                .filter(d -> "en".equals(d.getLang()))
                .findFirst()
                .map(Description::getValue)
                .orElse("");
    }

    private static final List<String> CVSS_VERSION_PRIORITY = List.of(
            "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"
    );

    public CvssData findBestCvssData() {
        if (metrics == null) return null;
        for (String versionKey : CVSS_VERSION_PRIORITY) {
            CvssData data = findPrimaryScore(metrics.get(versionKey));
            if (data != null) return data;
        }
        return null;
    }

    public double getBaseScore() {
        CvssData data = findBestCvssData();
        return data != null ? data.getBaseScore() : 0.0;
    }

    public String getBaseSeverity() {
        CvssData data = findBestCvssData();
        return data != null ? data.getBaseSeverity() : null;
    }

    private CvssData findPrimaryScore(List<CvssMetric> metricList) {
        if (metricList == null || metricList.isEmpty()) return null;
        return metricList.stream()
                .filter(m -> "Primary".equals(m.getType()))
                .map(CvssMetric::getCvssData)
                .filter(cvssData -> cvssData != null) // ssvcV203처럼 cvssData가 없는 항목 걸러냄
                .findFirst()
                .orElse(metricList.get(0).getCvssData());
    }

    public String getId() {
        return id;
    }

    public String getLastModified() {
        return lastModified;
    }

    public List<Description> getDescriptions() {
        return descriptions;
    }

    public Metrics getMetrics() {
        return metrics;
    }

    public List<NvdConfiguration> getConfigurations() {
        return configurations;
    }
}