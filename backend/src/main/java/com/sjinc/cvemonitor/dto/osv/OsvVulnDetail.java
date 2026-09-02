package com.sjinc.cvemonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** GET /v1/vulns/{id} 응답 (필요한 필드만 매핑). */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvVulnDetail {
    private String id;
    private String summary;
    private List<String> aliases; // CVE-xxxx 형태가 여기 섞여 있음
    private List<OsvSeverity> severity;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    public List<String> getAliases() { return aliases; }
    public void setAliases(List<String> aliases) { this.aliases = aliases; }
    public List<OsvSeverity> getSeverity() { return severity; }
    public void setSeverity(List<OsvSeverity> severity) { this.severity = severity; }
}