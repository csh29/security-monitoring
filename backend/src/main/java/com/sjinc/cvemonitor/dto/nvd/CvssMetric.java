package com.sjinc.cvemonitor.dto.nvd;
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
    private String source;
    private String type;      // "Primary" 또는 "Secondary"
    private CvssData cvssData;

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public CvssData getCvssData() { return cvssData; }
    public void setCvssData(CvssData cvssData) { this.cvssData = cvssData; }
}