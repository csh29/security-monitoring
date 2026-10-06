package com.sjinc.securitymonitor.dto.nvd;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * CVSS 점수의 핵심 값(base score, base severity)을 담는 DTO.
 *
 * <p>이 시스템의 등급 분류(크리티컬 = 즉시 메일 / 낮은 등급 = 주간 다이제스트) 로직이
 * 바로 이 클래스의 값을 기준으로 동작하게 된다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CvssData {

    /** CVSS 기본 점수 (0.0 ~ 10.0). 숫자 자체를 정렬/비교 기준으로 쓸 때 사용. */
    private double baseScore;

    /** CVSS 심각도 등급 문자열. "LOW" / "MEDIUM" / "HIGH" / "CRITICAL" 중 하나. */
    private String baseSeverity;

    public double getBaseScore() { return baseScore; }
    public void setBaseScore(double baseScore) { this.baseScore = baseScore; }
    public String getBaseSeverity() { return baseSeverity; }
    public void setBaseSeverity(String baseSeverity) { this.baseSeverity = baseSeverity; }
}