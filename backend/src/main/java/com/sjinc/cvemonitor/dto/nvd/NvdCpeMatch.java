package com.sjinc.cvemonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * NVD가 구조화된 형태로 내려주는 "이 CPE(제품)의 이 버전 범위가 취약하다"는 사실 하나.
 *
 * <p>{@code versionStart/EndIncluding/Excluding}은 명시되지 않은 것도 있다 — 예를 들어
 * {@code versionEndExcluding}만 있으면 "그 버전 미만은 전부 취약"이라는 뜻이다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NvdCpeMatch {

    private boolean vulnerable;
    private String criteria;
    private String versionStartIncluding;
    private String versionStartExcluding;
    private String versionEndIncluding;
    private String versionEndExcluding;

    public boolean isVulnerable() { return vulnerable; }
    public void setVulnerable(boolean vulnerable) { this.vulnerable = vulnerable; }
    public String getCriteria() { return criteria; }
    public void setCriteria(String criteria) { this.criteria = criteria; }
    public String getVersionStartIncluding() { return versionStartIncluding; }
    public void setVersionStartIncluding(String versionStartIncluding) { this.versionStartIncluding = versionStartIncluding; }
    public String getVersionStartExcluding() { return versionStartExcluding; }
    public void setVersionStartExcluding(String versionStartExcluding) { this.versionStartExcluding = versionStartExcluding; }
    public String getVersionEndIncluding() { return versionEndIncluding; }
    public void setVersionEndIncluding(String versionEndIncluding) { this.versionEndIncluding = versionEndIncluding; }
    public String getVersionEndExcluding() { return versionEndExcluding; }
    public void setVersionEndExcluding(String versionEndExcluding) { this.versionEndExcluding = versionEndExcluding; }
}
