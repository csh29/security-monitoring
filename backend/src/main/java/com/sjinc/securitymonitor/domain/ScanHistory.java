package com.sjinc.securitymonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 스캔 1회의 실행 기록(ScanSnapshot은 앱당 최신 하나만 덮어써서 이력이 남지 않는다).
 * 앱은 FK가 아니라 값으로 복사해 둔다 — FK면 앱을 못 지우고, 함께 지우면 이력이 사라지므로 수명을 분리한다.
 */
@Entity
@Table(name = "scan_histories", indexes = @Index(name = "ix_scan_histories_started_at", columnList = "started_at"))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(access = AccessLevel.PRIVATE)
public class ScanHistory {

    public static final String RUNNING = "RUNNING";
    public static final String SUCCESS = "SUCCESS";
    public static final String FAILED = "FAILED";

    /** 화면에 보여줄 오류 문구 최대 길이. 컬럼 길이와 맞춘다. */
    private static final int ERROR_MESSAGE_MAX = 500;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "scan_history_id")
    private Long id;

    @Column(name = "app_id", nullable = false)
    private Long appId;

    @Column(name = "system_name", nullable = false)
    private String systemName;

    @Column(name = "repo_url", nullable = false)
    private String repoUrl;

    @Column(nullable = false)
    private String branch;

    /** 스캔을 실행한 로그인 아이디. */
    @Column(name = "requested_by")
    private String requestedBy;

    /**
     * RUNNING / SUCCESS / FAILED. 시작할 때 RUNNING으로 먼저 저장한다 — clone·Maven·NVD 조회로 수 분씩 걸리는
     * 작업이라, 끝날 때 한 번에 쓰면 도는 동안 이력 화면에 아무것도 안 보인다. 서버가 스캔 도중 죽으면 RUNNING으로
     * 남는데, 그건 "끝났다는 기록이 없다"는 사실 그대로라 따로 보정하지 않는다.
     */
    @Column(nullable = false, length = 20)
    private String status;

    @Column(name = "started_at", nullable = false)
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;

    /** 스캔한 의존성 수(ScanResult.totalDependenciesScanned). */
    @Column(name = "dependency_count")
    private Integer dependencyCount;

    /** 이번 스캔에서 발견된 (CVE, 아티팩트) 조합 수(ScanResult.totalVulnerabilitiesFound). */
    @Column(name = "vulnerability_count")
    private Integer vulnerabilityCount;

    /** 스캔 전엔 OPEN이 아니었는데 스캔 후 OPEN인 건 — 처음 발견됐거나, 해결됐다가 다시 걸린 것. */
    @Column(name = "new_count")
    private Integer newCount;

    /** 이번 스캔에서 안 걸려 RESOLVED로 바뀐 건(resolveMissingVulnerabilities). */
    @Column(name = "resolved_count")
    private Integer resolvedCount;

    /** NVD 조회 실패로 저장하지 못한 건. 0이 아니면 이 회차의 신규·해결 건수도 불완전하다. */
    @Column(name = "failed_cve_count")
    private Integer failedCveCount;

    @Column(name = "error_message", length = ERROR_MESSAGE_MAX)
    private String errorMessage;

    public static ScanHistory start(App app, String requestedBy) {
        return ScanHistory.builder()
                .appId(app.getId())
                .systemName(app.getSystemName())
                .repoUrl(app.getRepoUrl())
                .branch(app.getBranch())
                .requestedBy(requestedBy)
                .status(RUNNING)
                .startedAt(LocalDateTime.now())
                .build();
    }

    public void succeed(int dependencyCount, int vulnerabilityCount, int newCount, int resolvedCount, int failedCveCount) {
        this.status = SUCCESS;
        this.finishedAt = LocalDateTime.now();
        this.dependencyCount = dependencyCount;
        this.vulnerabilityCount = vulnerabilityCount;
        this.newCount = newCount;
        this.resolvedCount = resolvedCount;
        this.failedCveCount = failedCveCount;
    }

    public void fail(String errorMessage) {
        this.status = FAILED;
        this.finishedAt = LocalDateTime.now();
        this.errorMessage = errorMessage != null && errorMessage.length() > ERROR_MESSAGE_MAX
                ? errorMessage.substring(0, ERROR_MESSAGE_MAX)
                : errorMessage;
    }
}
