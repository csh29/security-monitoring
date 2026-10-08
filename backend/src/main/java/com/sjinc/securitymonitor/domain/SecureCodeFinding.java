package com.sjinc.securitymonitor.domain;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * 시큐어코딩 점검(Semgrep)이 앱 하나에서 찾은 보안약점 한 건.
 *
 * <p>키는 (app_id, fingerprint)다. 지문은 줄 번호가 아니라 "규칙 + 파일 + 걸린 코드 내용"으로 만든다
 * (SecureCodeSnippetBuilder) — 줄 번호를 키로 쓰면 파일 위쪽에 한 줄만 추가돼도 모든 탐지가 "해결 + 신규"로 바뀌어
 * 사람이 남긴 오탐 판단이 전부 날아간다. 반대로 걸린 코드를 고치면 지문이 바뀌어 새 건이 되는데, 코드가 바뀌었으면
 * 판단도 다시 하는 게 맞아서 그대로 둔다.
 *
 * <p>앱을 FK로 참조하지 않는다(ScanHistory와 같은 이유) — 탐지가 생긴 앱을 앱 관리에서 못 지우게 되는 걸 피한다.
 * 지워진 앱의 행은 조회에서 빠진다(SecureCodeFindingService).
 */
@Entity
@Table(name = "secure_code_findings",
        uniqueConstraints = @UniqueConstraint(columnNames = {"app_id", "fingerprint"}),
        indexes = @Index(name = "ix_secure_code_findings_app", columnList = "app_id"))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(access = AccessLevel.PRIVATE)
public class SecureCodeFinding {

    public static final String OPEN = "OPEN";
    public static final String RESOLVED = "RESOLVED";
    /** 사람이 분석해 보니 실제 취약점이 아니었다. */
    public static final String FALSE_POSITIVE = "FALSE_POSITIVE";
    /** 실제 약점이지만 다른 통제가 있거나 영향이 작아 고치지 않기로 했다. */
    public static final String ACCEPTED = "ACCEPTED";

    /** 공통코드 SC_STATUS와 같은 값. 화면 select·뱃지가 이 값을 그대로 쓴다. */
    public static final Set<String> STATUSES = Set.of(OPEN, RESOLVED, FALSE_POSITIVE, ACCEPTED);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "secure_code_finding_id")
    private Long id;

    @Column(name = "app_id", nullable = false)
    private Long appId;

    @Column(nullable = false, length = 64)
    private String fingerprint;

    @Column(name = "rule_id", nullable = false)
    private String ruleId;

    /** 행안부 SW 보안약점 진단가이드의 분류(예: 입력데이터 검증 및 표현)와 항목명(예: SQL 삽입). 규칙 메타데이터 값. */
    @Column(name = "kisa_category")
    private String kisaCategory;

    @Column(name = "kisa_name")
    private String kisaName;

    private String cwe;

    /** Semgrep 심각도(ERROR/WARNING/INFO)를 공통코드 SEVERITY 값(HIGH/MEDIUM/LOW)으로 바꾼 값. */
    private String severity;

    /** 저장소 루트 기준 경로(구분자 /). */
    @Column(name = "file_path", nullable = false, length = 1000)
    private String filePath;

    @Column(name = "start_line")
    private Integer startLine;

    @Column(name = "end_line")
    private Integer endLine;

    @Column(length = 1000)
    private String message;

    /** 걸린 줄을 감싼 메서드(매퍼 XML이면 구문, 못 찾으면 앞뒤 5줄, 최대 80줄). 하드코드된 비밀값 규칙은 값을 가린 뒤 저장한다(DB가 비밀번호 모음이 되지 않게). */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String snippet;

    @Column(name = "snippet_start_line")
    private Integer snippetStartLine;

    /**
     * MyBatis ${} 연계 추적 판정(DollarVerdict.Safety 이름) — 값이 클라이언트에서 오는지 서버가 세팅하는지 Java 소스를 따라가 본 결과.
     * severity는 이 판정으로 다시 매긴 값이다(안전 판정이면 LOW). ${} 규칙이 아니거나 추적하지 못했으면 null(Semgrep 등급 그대로).
     */
    @Column(name = "trace_safety", length = 30)
    private String traceSafety;

    /** 판정 근거 — 값이 지나온 길(호출 쪽 → 매퍼 쪽), 한 줄에 한 걸음. */
    @Lob
    @Column(name = "trace_evidence", columnDefinition = "CLOB")
    private String traceEvidence;

    /**
     * AI 판별에 보낸(보낼) 코드 문맥 — 걸린 줄을 감싼 메서드(SecureCodeSnippetBuilder.withAiContext). clone은 점검이 끝나면 지워지므로
     * 점검 때 만들어 둔다. AI 판별 대상(결정론으로 못 정한 높은 등급)일 때만 채운다.
     */
    /**
     * 연계 추적 근거 걸음마다 그 줄 주변 코드(TraceStepCode 목록 JSON, 근거와 같은 순서) — 상세보기에서 근거를 누르면 펼쳐 본다.
     * 근거는 다른 파일·메서드를 가리키는데 화면용 조각은 걸린 줄 주변뿐이라 따로 둔다. clone은 점검이 끝나면 지우므로 점검 때 만든다.
     */
    @Lob
    @Column(name = "trace_code", columnDefinition = "CLOB")
    private String traceCode;

    @Lob
    @Column(name = "ai_context", columnDefinition = "CLOB")
    private String aiContext;

    @Column(name = "ai_context_start_line")
    private Integer aiContextStartLine;

    /**
     * AI 판별 결과(VULNERABLE/NOT_VULNERABLE/UNCERTAIN). 화면에 참고로만 보여주고 처리여부는 바꾸지 않는다 — 오탐 처리는 사람이 한다.
     * 판별에 쓴 입력(코드 문맥·연계 추적 근거)의 해시를 aiInputHash에 같이 둔다. 재점검으로 입력이 바뀌면 해시가 달라져
     * 그 판별은 화면에서 숨기고 다시 대기가 된다(SecureCodeAiReviewService).
     */
    @Column(name = "ai_verdict", length = 20)
    private String aiVerdict;

    @Column(name = "ai_confidence", length = 10)
    private String aiConfidence;

    @Column(name = "ai_reasoning", length = 2000)
    private String aiReasoning;

    @Column(name = "ai_input_hash", length = 64)
    private String aiInputHash;

    @Column(name = "ai_reviewed_at")
    private LocalDateTime aiReviewedAt;

    @Column(nullable = false, length = 20)
    private String status;

    /**
     * 사람이 처리여부를 바꿨는가. true면 같은 지문이 다시 탐지돼도 스캔 결과로 상태를 바꾸지 않는다 — 오탐으로 처리한 건이
     * 재점검마다 OPEN으로 돌아오면 사람의 판단이 매번 지워진다(Vulnerability.statusManual과 같은 규칙).
     */
    @Column(name = "status_manual")
    private Boolean statusManual;

    @Column(name = "status_changed_by")
    private String statusChangedBy;

    @Column(length = 1000)
    private String remark;

    @Column(name = "first_detected_at", nullable = false)
    private LocalDateTime firstDetectedAt;

    @Column(name = "last_detected_at", nullable = false)
    private LocalDateTime lastDetectedAt;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    public static SecureCodeFinding detect(Long appId, DetectedFinding detected, LocalDateTime now) {
        SecureCodeFinding finding = SecureCodeFinding.builder()
                .appId(appId)
                .fingerprint(detected.fingerprint())
                .status(OPEN)
                .firstDetectedAt(now)
                .build();
        finding.applyDetected(detected, now);
        return finding;
    }

    /**
     * 같은 지문이 다시 탐지됐다. 줄 번호·코드 조각은 최신으로 바꾸고(위에 코드가 추가되면 줄이 밀린다), 스캔이 RESOLVED로
     * 만들어 둔 건은 다시 OPEN으로 되돌린다. 사람이 정한 상태는 유지한다.
     */
    public void redetect(DetectedFinding detected, LocalDateTime now) {
        applyDetected(detected, now);
        if (!Boolean.TRUE.equals(statusManual) && RESOLVED.equals(status)) {
            status = OPEN;
            resolvedAt = null;
        }
    }

    /** 이번 점검에서 안 걸렸다(코드를 고쳤거나 지웠다). OPEN인 건만 바꾼다 — 사람이 정한 상태는 그대로 둔다. */
    public boolean resolveByScan(LocalDateTime now) {
        if (!OPEN.equals(status) || Boolean.TRUE.equals(statusManual)) {
            return false;
        }
        status = RESOLVED;
        resolvedAt = now;
        return true;
    }

    /**
     * 이 탐지를 낸 규칙을 폐기했다(SecureCodeRuleRetirement). 규칙셋에 없는 규칙의 탐지는 재점검이 해결 처리하지 않으므로(지운 규칙 ≠ 고친 코드)
     * 그대로 두면 OPEN으로 영원히 남는다. OPEN이고 사람이 정하지 않은 건만 RESOLVED로 바꾸고 이유를 비고에 남긴다(사람이 쓴 비고는 앞에 둔다).
     */
    public boolean retireRule(String reason, LocalDateTime now) {
        if (!OPEN.equals(status) || Boolean.TRUE.equals(statusManual)) {
            return false;
        }
        status = RESOLVED;
        resolvedAt = now;
        String merged = remark == null || remark.isBlank() ? reason : remark + " / " + reason;
        remark = merged.length() > 1000 ? merged.substring(0, 1000) : merged;
        statusChangedBy = "system";
        return true;
    }

    /** 화면에서 사람이 처리여부를 바꾼다. OPEN으로 되돌리면 다시 스캔 결과를 따른다. */
    public void changeStatusManually(String newStatus, String changedBy, LocalDateTime now) {
        if (!STATUSES.contains(newStatus)) {
            throw new IllegalArgumentException("처리여부 값이 올바르지 않습니다: " + newStatus);
        }
        status = newStatus;
        statusManual = OPEN.equals(newStatus) ? null : Boolean.TRUE;
        resolvedAt = RESOLVED.equals(newStatus) ? now : null;
        statusChangedBy = changedBy;
    }

    /** 비고만 바꾼다. 처리여부(statusManual)는 건드리지 않는다(Vulnerability.changeRemark와 같은 이유). */
    public void changeRemark(String newRemark, String changedBy) {
        remark = newRemark;
        statusChangedBy = changedBy;
    }

    /** AI 판별 결과를 저장한다. 값 검증은 SecureCodeAiReviewService가 한다. */
    public void applyAiReview(String verdict, String confidence, String reasoning, String inputHash, LocalDateTime now) {
        aiVerdict = verdict;
        aiConfidence = confidence;
        aiReasoning = reasoning;
        aiInputHash = inputHash;
        aiReviewedAt = now;
    }

    private void applyDetected(DetectedFinding detected, LocalDateTime now) {
        ruleId = detected.ruleId();
        kisaCategory = detected.kisaCategory();
        kisaName = detected.kisaName();
        cwe = detected.cwe();
        severity = detected.severity();
        filePath = detected.filePath();
        startLine = detected.startLine();
        endLine = detected.endLine();
        message = detected.message();
        snippet = detected.snippet();
        snippetStartLine = detected.snippetStartLine();
        // 재점검마다 최신 판정으로 바꾼다 — 우회 경로를 막는 등 연계 코드가 바뀌면 ${} 줄이 그대로여도 판정이 달라진다.
        traceSafety = detected.traceSafety();
        traceEvidence = detected.traceEvidence();
        traceCode = detected.traceCode();
        // AI 판별 결과는 지우지 않는다 — 입력이 그대로면 다시 보낼 필요가 없고, 바뀌었으면 해시가 달라 숨겨지고 다시 대기가 된다.
        aiContext = detected.aiContext();
        aiContextStartLine = detected.aiContextStartLine();
        lastDetectedAt = now;
    }
}
