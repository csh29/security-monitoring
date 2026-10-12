package com.sjinc.securitymonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CVE 하나의 CVSS 메트릭 모음 — 버전별 키({@code cvssMetricV31} 등)를 모두 받아 두고, 쓸 버전은 CveItem이 우선순위대로 고른다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Metrics {
    private final Map<String, List<CvssMetric>> byVersion = new LinkedHashMap<>();

    @JsonAnySetter
    public void set(String key, List<CvssMetric> value) {
        byVersion.put(key, value);
    }

    public List<CvssMetric> get(String versionKey) {
        return byVersion.get(versionKey);
    }
}