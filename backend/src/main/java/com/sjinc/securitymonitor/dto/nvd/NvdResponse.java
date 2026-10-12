package com.sjinc.securitymonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * NVD CVE API 2.0(/rest/json/cves/2.0)의 최상위 응답 객체. 쓰지 않는 필드는 매핑하지 않고 무시한다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NvdResponse {

    /** 조건에 일치하는 전체 CVE 개수 (페이지네이션 시 참고용, 실제 반환 개수와 다를 수 있음). */
    private int totalResults;

    /** 이번 응답에 포함된 취약점 목록. 각 항목은 CVE 하나를 감싸는 래퍼(VulnerabilityWrapper)이다. */
    private List<VulnerabilityWrapper> vulnerabilities;

    public int getTotalResults() { return totalResults; }
    public void setTotalResults(int totalResults) { this.totalResults = totalResults; }
    public List<VulnerabilityWrapper> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<VulnerabilityWrapper> vulnerabilities) { this.vulnerabilities = vulnerabilities; }
}