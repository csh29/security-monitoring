package com.sjinc.securitymonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvSeverity {
    private String type;  // 예: "CVSS_V3"
    private String score; // 예: "CVSS:3.1/AV:N/AC:L/..."

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getScore() { return score; }
    public void setScore(String score) { this.score = score; }
}