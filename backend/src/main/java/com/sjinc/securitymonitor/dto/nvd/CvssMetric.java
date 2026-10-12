package com.sjinc.securitymonitor.dto.nvd;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * CVSS 메트릭 항목 하나 — 점수 데이터(cvssData)와 source·type(Primary/Secondary) 메타 정보.
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