package com.sjinc.cvemonitor.dto.cve;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

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
    private List<CvssMetric> cvssMetricV31;
    private List<CvssMetric> cvssMetricV3;  // 일부 구형 CVE는 여전히 이 필드로 옴
    private List<CvssMetric> cvssMetricV2;  // v3 계열이 아예 없는 아주 오래된 CVE용 폴백

    public List<CvssMetric> getCvssMetricV31() { return cvssMetricV31; }
    public void setCvssMetricV31(List<CvssMetric> cvssMetricV31) { this.cvssMetricV31 = cvssMetricV31; }
    public List<CvssMetric> getCvssMetricV3() { return cvssMetricV3; }
    public void setCvssMetricV3(List<CvssMetric> cvssMetricV3) { this.cvssMetricV3 = cvssMetricV3; }
    public List<CvssMetric> getCvssMetricV2() { return cvssMetricV2; }
    public void setCvssMetricV2(List<CvssMetric> cvssMetricV2) { this.cvssMetricV2 = cvssMetricV2; }
}