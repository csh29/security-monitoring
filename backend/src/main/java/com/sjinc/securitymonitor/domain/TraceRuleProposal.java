package com.sjinc.securitymonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 코드 점검이 만든 추적 규칙(trace-rules.yml) 변경 한 건과 그 처리 결과. 판정을 느슨하게 하는 변경은 확인 대기(PENDING)로 두었다가
 * 사람이 반영하고, 점검 중 바로 반영한 변경(AUTO_APPLIED)도 "언제 왜 규칙이 바뀌었나"를 볼 수 있게 함께 남긴다.
 *
 * <p>같은 변경(changeKey)이 점검마다 다시 나오면 새로 만들지 않고 마지막 확인 시각만 바꾼다. 사람이 무시(DISMISSED)한 변경은 다시 묻지 않는다.
 * 앱은 값으로만 둔다(SecureCodeScan과 같은 이유 — FK면 앱을 못 지운다).
 */
@Entity
@Table(name = "trace_rule_proposals", indexes = {
        @Index(name = "ix_trace_rule_proposals_key", columnList = "change_key"),
        @Index(name = "ix_trace_rule_proposals_status", columnList = "status")})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TraceRuleProposal {

    public static final String PENDING = "PENDING";
    public static final String APPLIED = "APPLIED";
    public static final String AUTO_APPLIED = "AUTO_APPLIED";
    public static final String DISMISSED = "DISMISSED";
    /** 확인 대기였는데 같은 앱을 다시 점검했을 때 나오지 않음(코드가 바뀌었거나 규칙이 이미 맞음) — 반영할 근거가 없어졌다. */
    public static final String OBSOLETE = "OBSOLETE";

    private static final int TEXT_MAX = 1000;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "trace_rule_proposal_id")
    private Long id;

    /** 이 변경을 처음(또는 마지막으로) 만든 점검의 앱. */
    @Column(name = "app_id", nullable = false)
    private Long appId;

    @Column(name = "system_name", nullable = false)
    private String systemName;

    /** TraceRuleChange.key — 같은 변경을 묶는 키. */
    @Column(name = "change_key", nullable = false, length = TEXT_MAX)
    private String changeKey;

    /** TraceRuleChange.Type 이름. */
    @Column(name = "change_type", nullable = false, length = 40)
    private String changeType;

    /** 반영할 때 그대로 다시 적용하는 TraceRuleChange(JSON). 근거도 여기 들어 있다. */
    @Lob
    @Column(name = "change_json", nullable = false, columnDefinition = "CLOB")
    private String changeJson;

    @Column(length = TEXT_MAX)
    private String summary;

    /** PENDING / APPLIED / AUTO_APPLIED / DISMISSED / OBSOLETE. */
    @Column(nullable = false, length = 20)
    private String status;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    /** 점검에서 마지막으로 다시 나온 시각. */
    @Column(name = "last_seen_at", nullable = false)
    private LocalDateTime lastSeenAt;

    @Column(name = "decided_by")
    private String decidedBy;

    @Column(name = "decided_at")
    private LocalDateTime decidedAt;

    /** 처리 결과 설명(이미 반영돼 있었음 등). */
    @Column(name = "decision_note", length = 500)
    private String decisionNote;

    public static TraceRuleProposal create(Long appId, String systemName, String changeKey, String changeType,
                                           String changeJson, String summary, String status) {
        TraceRuleProposal p = new TraceRuleProposal();
        p.appId = appId;
        p.systemName = systemName;
        p.changeKey = cut(changeKey, TEXT_MAX);
        p.changeType = changeType;
        p.changeJson = changeJson;
        p.summary = cut(summary, TEXT_MAX);
        p.status = status;
        p.createdAt = LocalDateTime.now();
        p.lastSeenAt = p.createdAt;
        if (AUTO_APPLIED.equals(status)) {
            p.decidedBy = "자동";
            p.decidedAt = p.createdAt;
        }
        return p;
    }

    /** 같은 변경이 다시 나왔다 — 근거(줄 번호 등)는 최신으로. */
    public void seenAgain(Long appId, String systemName, String changeJson, String summary) {
        this.appId = appId;
        this.systemName = systemName;
        this.changeJson = changeJson;
        this.summary = cut(summary, TEXT_MAX);
        this.lastSeenAt = LocalDateTime.now();
    }

    public void decide(String status, String decidedBy, String note) {
        this.status = status;
        this.decidedBy = decidedBy;
        this.decidedAt = LocalDateTime.now();
        this.decisionNote = cut(note, 500);
    }

    public boolean isPending() {
        return PENDING.equals(status);
    }

    private static String cut(String value, int max) {
        return value != null && value.length() > max ? value.substring(0, max) : value;
    }
}
