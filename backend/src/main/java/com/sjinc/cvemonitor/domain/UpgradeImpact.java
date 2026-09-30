package com.sjinc.cvemonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 라이브러리 업그레이드 한 건(coordinate, from → to)의 영향 분석 결과 — 릴리스 노트 근거로 AI가 정리한 breaking
 * change, 필요한 조치, 테스트할 곳.
 *
 * <p><b>앱이 아니라 (좌표, from, to) 단위로 하나만 둔다.</b> 이 분석은 라이브러리 릴리스 노트만 보고 결정되므로,
 * 여러 앱이 같은 Spring Boot 업그레이드를 하면 결과가 같다 — 앱마다 두면 같은 릴리스 노트를 앱 수만큼 읽혀
 * 과금된다(CveSummary를 CVE ID 단위로 둔 것과 같은 이유). "우리 코드가 영향받는가"는 앱마다 다르므로 여기 두지 않는다.
 *
 * <p>목록형 필드(breakingChanges 등)는 JSON 문자열로 둔다. 화면에서 통째로 읽기만 하고 항목 단위로 조회할 일이 없다.
 */
@Entity
@Table(name = "upgrade_impacts",
        uniqueConstraints = @UniqueConstraint(name = "uk_upgrade_impacts_key",
                columnNames = {"coordinate", "from_version", "to_version"}))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class UpgradeImpact {

    /** 릴리스 노트로 분석을 마쳤다. */
    public static final String ANALYZED = "ANALYZED";
    /** 어느 출처에서도 릴리스 노트를 못 찾았다 — 사람이 직접 확인해야 한다. 다시 대기로 잡지 않는다. */
    public static final String NO_SOURCE = "NO_SOURCE";
    /** 수집 도중 일시 오류(호출 한도 초과·네트워크)로 판단을 못 했다. 다음 배치에서 다시 대기로 잡힌다. */
    public static final String FETCH_FAILED = "FETCH_FAILED";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "upgrade_impact_id")
    private Long id;

    @Column(nullable = false)
    private String coordinate;

    @Column(name = "from_version", nullable = false)
    private String fromVersion;

    @Column(name = "to_version", nullable = false)
    private String toVersion;

    @Column(nullable = false, length = 20)
    private String status;

    /** LOW / MEDIUM / HIGH. ANALYZED일 때만 값이 있다. */
    @Column(length = 10)
    private String risk;

    /** high / medium / low. ANALYZED일 때만 값이 있다. */
    @Column(length = 10)
    private String confidence;

    /** [{summary, sourceUrl}] */
    @Lob
    @Column(name = "breaking_changes", columnDefinition = "CLOB")
    private String breakingChangesJson;

    /** ["..."] */
    @Lob
    @Column(name = "required_actions", columnDefinition = "CLOB")
    private String requiredActionsJson;

    /** ["..."] */
    @Lob
    @Column(name = "test_focus", columnDefinition = "CLOB")
    private String testFocusJson;

    /** 근거로 읽은 문서 [{kind, url}]. kind: GITHUB_RELEASE / GITLAB_RELEASE / CHANGELOG / JIRA / OFFICIAL_DOC */
    @Lob
    @Column(name = "sources", columnDefinition = "CLOB")
    private String sourcesJson;

    /** 수집·분석 중 사람이 알아야 할 사정(생략된 릴리스 노트, 버린 항목 수, 수집 실패 사유 등). */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String note;

    @Column(name = "analyzed_at", nullable = false)
    private LocalDateTime analyzedAt;

    public static UpgradeImpact of(String coordinate, String fromVersion, String toVersion) {
        return UpgradeImpact.builder().coordinate(coordinate).fromVersion(fromVersion).toVersion(toVersion).build();
    }

    public void apply(String status, String risk, String confidence, String breakingChangesJson,
                      String requiredActionsJson, String testFocusJson, String sourcesJson, String note) {
        this.status = status;
        this.risk = risk;
        this.confidence = confidence;
        this.breakingChangesJson = breakingChangesJson;
        this.requiredActionsJson = requiredActionsJson;
        this.testFocusJson = testFocusJson;
        this.sourcesJson = sourcesJson;
        this.note = note;
        this.analyzedAt = LocalDateTime.now();
    }
}
