package com.sjinc.cvemonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * OSV 단건 조회({@code POST /v1/query}) 응답. 배치 조회({@code /v1/querybatch})와 달리
 * id+modified만 주는 요약(OsvVulnRef)이 아니라, 상세 정보가 담긴 {@link OsvVulnDetail}을
 * 그 자리에서 바로 돌려준다 — 뒤이어 {@code /v1/vulns/{id}}를 또 호출할 필요가 없다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvQueryResponse {

    private List<OsvVulnDetail> vulns;

    public List<OsvVulnDetail> getVulns() { return vulns; }
    public void setVulns(List<OsvVulnDetail> vulns) { this.vulns = vulns; }
}
