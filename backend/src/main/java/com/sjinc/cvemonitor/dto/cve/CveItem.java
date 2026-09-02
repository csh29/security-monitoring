package com.sjinc.cvemonitor.dto.cve;

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

    /**
     * CVSS v3(또는 v3.1) 기준 base score(0.0 ~ 10.0)를 반환한다.
     * metrics 정보가 없거나 v3 점수가 없는 경우(구형 CVE 등) 0.0을 반환한다.
     *
     * <p>주의: NVD는 CVSS 버전에 따라 필드명이 {@code cvssMetricV3}가 아니라
     * {@code cvssMetricV31}로 내려오는 경우도 있다. 실제 응답을 확인해서
     * 필요하면 Metrics 쪽에 v31 필드도 함께 매핑해야 한다.
     */
    public double getBaseScore() {
        if (metrics == null) return 0.0;

        CvssData data = findPrimaryScore(metrics.getCvssMetricV31());
        if (data == null) data = findPrimaryScore(metrics.getCvssMetricV3());
        if (data == null) data = findPrimaryScore(metrics.getCvssMetricV2());

        return data != null ? data.getBaseScore() : 0.0;
    }

    private CvssData findPrimaryScore(List<CvssMetric> metricList) {
        if (metricList == null || metricList.isEmpty()) return null;
        return metricList.stream()
                .filter(m -> "Primary".equals(m.getType()))
                .map(CvssMetric::getCvssData)
                .findFirst()
                .orElse(metricList.get(0).getCvssData()); // Primary가 없으면 첫 번째라도 사용
    }

    /**
     * CVSS v3(또는 v3.1) 기준 심각도 등급("LOW"/"MEDIUM"/"HIGH"/"CRITICAL")을 반환한다.
     * metrics 정보가 없는 경우 null을 반환한다.
     */
    public String getBaseSeverity() {
        if (metrics == null || metrics.getCvssMetricV3() == null || metrics.getCvssMetricV3().isEmpty()) {
            return null;
        }
        return metrics.getCvssMetricV3().get(0).getCvssData().getBaseSeverity();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getLastModified() { return lastModified; }
    public void setLastModified(String lastModified) { this.lastModified = lastModified; }
    public List<Description> getDescriptions() { return descriptions; }
    public void setDescriptions(List<Description> descriptions) { this.descriptions = descriptions; }
    public Metrics getMetrics() { return metrics; }
    public void setMetrics(Metrics metrics) { this.metrics = metrics; }
}