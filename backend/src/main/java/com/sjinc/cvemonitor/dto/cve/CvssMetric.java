package com.sjinc.cvemonitor.dto.cve;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * CVSS 메트릭 항목 하나를 감싸는 래퍼.
 *
 * <p>NVD 응답에서 각 메트릭 항목은 점수 데이터(cvssData) 외에도
 * source, type(Primary/Secondary) 같은 메타 정보를 함께 갖고 있는데,
 * 현재는 실제 점수 데이터인 {@link #cvssData}만 사용한다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CvssMetric {

    /** 실제 CVSS 점수/심각도 데이터. */
    private CvssData cvssData;

    public CvssData getCvssData() { return cvssData; }
    public void setCvssData(CvssData cvssData) { this.cvssData = cvssData; }
}
