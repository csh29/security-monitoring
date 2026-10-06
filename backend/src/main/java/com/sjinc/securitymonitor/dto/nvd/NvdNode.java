package com.sjinc.securitymonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * configurations 안의 노드 하나. 보통 {@code operator: "OR"}에 cpeMatch 여러 개가 달려서
 * "이 중 하나라도 버전 범위에 들면 취약"을 표현한다. AND 조합(다른 제품과 함께 쓰일 때만
 * 취약한 조건부 케이스)은 이 시스템에서 아직 다루지 않는다 — cpeMatch를 전부 OR로 취급한다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NvdNode {

    private String operator;
    private List<NvdCpeMatch> cpeMatch;

    public String getOperator() { return operator; }
    public void setOperator(String operator) { this.operator = operator; }
    public List<NvdCpeMatch> getCpeMatch() { return cpeMatch; }
    public void setCpeMatch(List<NvdCpeMatch> cpeMatch) { this.cpeMatch = cpeMatch; }
}
