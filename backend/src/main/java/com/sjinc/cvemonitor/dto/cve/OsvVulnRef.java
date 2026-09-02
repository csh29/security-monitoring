package com.sjinc.cvemonitor.dto.cve;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * 배치 응답에 들어있는 취약점 참조 (요약 정보만, 상세는 /v1/vulns/{id}로 별도 조회).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvVulnRef {
    /** GHSA-xxxx 또는 CVE-xxxx 형태의 식별자. */
    private String id;

    /** 이 취약점 정보가 OSV 측에서 마지막으로 갱신된 시각. 캐시 무효화 판단에 사용 가능. */
    private String modified;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getModified() { return modified; }
    public void setModified(String modified) { this.modified = modified; }
}