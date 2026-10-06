package com.sjinc.securitymonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** GET /v1/vulns/{id} 응답 (필요한 필드만 매핑). */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvVulnDetail {
    private String id;
    private String summary;
    private List<String> aliases; // CVE-xxxx 형태가 여기 섞여 있음
    private List<OsvSeverity> severity;
    private List<OsvAffected> affected;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    public List<String> getAliases() { return aliases; }
    public void setAliases(List<String> aliases) { this.aliases = aliases; }
    public List<OsvSeverity> getSeverity() { return severity; }
    public void setSeverity(List<OsvSeverity> severity) { this.severity = severity; }
    public List<OsvAffected> getAffected() { return affected; }
    public void setAffected(List<OsvAffected> affected) { this.affected = affected; }

    /**
     * Maven 생태계 range들의 fixed 이벤트만 모아 중복 제거한 목록.
     * ranges/introduced 전체를 다 파싱하지 않고 "수정 버전 후보"만 뽑아 AI 판단 입력으로 넘기기 위한 용도라,
     * 브랜치가 여러 개면(예: 2.x/3.x 동시 패치) 여러 값이 그대로 후보로 남는다 — 그중 설치 버전과
     * 같은 라인을 고르는 건 AI(assess.system.md 규칙)의 몫이다.
     */
    public List<String> getFixedVersions() {
        if (affected == null) return List.of();
        Set<String> fixedVersions = new LinkedHashSet<>();
        for (OsvAffected a : affected) {
            if (a.getPackageInfo() == null || !"Maven".equals(a.getPackageInfo().getEcosystem())) continue;
            if (a.getRanges() == null) continue;
            for (OsvRange range : a.getRanges()) {
                if (range.getEvents() == null) continue;
                for (OsvEvent event : range.getEvents()) {
                    if (event.getFixed() != null) fixedVersions.add(event.getFixed());
                }
            }
        }
        return List.copyOf(fixedVersions);
    }
}