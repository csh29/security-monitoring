package com.sjinc.cvemonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CVE 하나에 대한 CVSS 메트릭 모음.
 *
 * <p>NVD 응답 구조상 metrics 안에는 CVSS 버전별로
 * {@code cvssMetricV2}, {@code cvssMetricV30}, {@code cvssMetricV31} 등이
 * 나뉘어 내려올 수 있는데, 현재는 v3 계열만 사용하고 있어 {@link #cvssMetricV3}만
 * 매핑한 상태다.
 *
 * <p>TODO: 일부 CVE는 v3 대신 v3.1({@code cvssMetricV31})로만 내려오는 경우가 있어
 * 해당 필드를 놓칠 수 있다. 실제 데이터 확인 후 v31 필드 추가 매핑이 필요할 수 있음.
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