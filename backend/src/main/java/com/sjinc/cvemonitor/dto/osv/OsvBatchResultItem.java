package com.sjinc.cvemonitor.dto.osv;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * OSV /v1/querybatch 응답의 개별 결과 항목.
 * 요청 시 queries 배열과 같은 순서로 매칭된다 (인덱스 기반, id로 매칭 아님).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvBatchResultItem {
    /** 이 의존성에 매칭된 취약점 목록. 없으면 빈 배열. */
    private List<OsvVulnRef> vulns;

    public List<OsvVulnRef> getVulns() { return vulns; }
    public void setVulns(List<OsvVulnRef> vulns) { this.vulns = vulns; }
}