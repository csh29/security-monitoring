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
 * 시큐어코딩 점검 1회의 실행 기록. 라이브러리 스캔 이력(ScanHistory)과 테이블을 나눈 이유는 건수 컬럼이 전혀 다르기
 * 때문이다(의존성 수·CVE 조회 실패 ↔ 점검 파일 수·분석 실패 파일 수). 앱을 값으로 복사해 두는 이유는 ScanHistory와 같다.
 */
@Entity
@Table(name = "secure_code_scans", indexes = @Index(name = "ix_secure_code_scans_started_at", columnList = "started_at"))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(access = AccessLevel.PRIVATE)
public class SecureCodeScan {

    public static final String RUNNING = "RUNNING";
    public static final String SUCCESS = "SUCCESS";
    public static final String FAILED = "FAILED";

    private static final int ERROR_MESSAGE_MAX = 500;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "secure_code_scan_id")
    private Long id;

    @Column(name = "app_id", nullable = false)
    private Long appId;

    @Column(name = "system_name", nullable = false)
    private String systemName;

    /** Git 점검만 있다. 업로드 점검은 null이고 아래 upload* 값이 있다. */
    @Column(name = "repo_url")
    private String repoUrl;

    @Column
    private String branch;

    /** 업로드 점검에서 올린 zip 이름과 내용 해시 — 어떤 소스로 점검했는지 나중에 맞춰 볼 수 있게(Git의 브랜치 대신). */
    @Column(name = "upload_file_name")
    private String uploadFileName;

    @Column(name = "upload_sha256", length = 64)
    private String uploadSha256;

    @Column(name = "requested_by")
    private String requestedBy;

    /** RUNNING / SUCCESS / FAILED. 서버가 도중에 죽으면 RUNNING으로 남는다(ScanHistory와 같다). */
    @Column(nullable = false, length = 20)
    private String status;

    @Column(name = "started_at", nullable = false)
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;

    /** Semgrep이 실제로 읽은 파일 수. */
    @Column(name = "file_count")
    private Integer fileCount;

    /** 이번 점검에서 탐지된 건수(처리여부와 무관하게 이번에 걸린 전부). */
    @Column(name = "finding_count")
    private Integer findingCount;

    /** 점검 전엔 OPEN이 아니었는데 점검 후 OPEN인 건 — 처음 걸렸거나, 해결됐다가 다시 걸린 것. */
    @Column(name = "new_count")
    private Integer newCount;

    /** 이번 점검에서 안 걸려 RESOLVED로 바뀐 건. */
    @Column(name = "resolved_count")
    private Integer resolvedCount;

    /**
     * Semgrep이 해석하지 못했거나 시간 초과로 끝까지 못 본 파일 수. 0이 아니면 그 파일은 "약점이 없는 것"이 아니라
     * "못 본 것"이다 — 그 파일의 기존 탐지는 해결 처리하지 않는다.
     */
    @Column(name = "failed_file_count")
    private Integer failedFileCount;

    /** 점검 건수가 크게 바뀌었을 때 코드가 바뀐 건지 엔진·규칙이 바뀐 건지 구분하려고 남긴다. */
    @Column(name = "engine_version", length = 50)
    private String engineVersion;

    /** 규칙 파일 내용의 해시 앞 12자리(RuleSetLoader). */
    @Column(name = "ruleset_version", length = 50)
    private String rulesetVersion;

    @Column(name = "error_message", length = ERROR_MESSAGE_MAX)
    private String errorMessage;

    public static SecureCodeScan start(App app, String requestedBy) {
        return SecureCodeScan.builder()
                .appId(app.getId())
                .systemName(app.getSystemName())
                .repoUrl(app.getRepoUrl())
                .branch(app.getBranch())
                .requestedBy(requestedBy)
                .status(RUNNING)
                .startedAt(LocalDateTime.now())
                .build();
    }

    public static SecureCodeScan startUpload(App app, String requestedBy, String fileName) {
        return SecureCodeScan.builder()
                .appId(app.getId())
                .systemName(app.getSystemName())
                .uploadFileName(fileName != null && fileName.length() > 255 ? fileName.substring(0, 255) : fileName)
                .requestedBy(requestedBy)
                .status(RUNNING)
                .startedAt(LocalDateTime.now())
                .build();
    }

    /** 업로드한 zip의 내용 해시(받는 동안 계산해 점검 시작 뒤에 안다). */
    public void recordUploadHash(String sha256) {
        this.uploadSha256 = sha256;
    }

    public void succeed(int fileCount, int findingCount, int newCount, int resolvedCount, int failedFileCount,
                        String engineVersion, String rulesetVersion) {
        this.status = SUCCESS;
        this.finishedAt = LocalDateTime.now();
        this.fileCount = fileCount;
        this.findingCount = findingCount;
        this.newCount = newCount;
        this.resolvedCount = resolvedCount;
        this.failedFileCount = failedFileCount;
        this.engineVersion = engineVersion;
        this.rulesetVersion = rulesetVersion;
    }

    public void fail(String errorMessage) {
        this.status = FAILED;
        this.finishedAt = LocalDateTime.now();
        this.errorMessage = errorMessage != null && errorMessage.length() > ERROR_MESSAGE_MAX
                ? errorMessage.substring(0, ERROR_MESSAGE_MAX)
                : errorMessage;
    }
}
