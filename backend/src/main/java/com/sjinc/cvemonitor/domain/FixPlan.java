package com.sjinc.cvemonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** 앱 하나에 걸린 취약 CVE들을 취합해서 AI가 제안한 pom.xml 수정안. 항상 사람이 검토해야 하므로 자동 적용은 하지 않는다. */
@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FixPlan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "app_id", referencedColumnName = "app_id", unique = true)
    private App app;

    private String strategy; // PARENT_UPGRADE / PROPERTY_OVERRIDE / MIXED

    @Lob
    @Column(columnDefinition = "CLOB")
    private String pomXml; // AI가 제안한, 수정이 반영된 pom.xml 전체

    @Lob
    @Column(columnDefinition = "CLOB")
    private String unresolvedCves; // 버전 업그레이드만으론 안 풀리는 CVE와 이유

    @Lob
    @Column(columnDefinition = "CLOB")
    private String reasoning;

    // AI 판단 대상(HIGH/CRITICAL)에서 제외된 LOW/MEDIUM CVE 요약. AI가 아니라 자바가 DB 조회로 채운다.
    @Lob
    @Column(columnDefinition = "CLOB")
    private String lowSeverityNote;

    @Builder.Default
    private String status = "PENDING_REVIEW"; // 사람이 검토해서 적용/반려하기 전까지는 항상 이 상태

    private LocalDateTime createdAt;

    public void applyPlan(String strategy, String pomXml, String unresolvedCves, String reasoning) {
        this.strategy = strategy;
        this.pomXml = pomXml;
        this.unresolvedCves = unresolvedCves;
        this.reasoning = reasoning;
        this.status = "PENDING_REVIEW";
        this.createdAt = LocalDateTime.now();
    }

    public void attachLowSeverityNote(String lowSeverityNote) {
        this.lowSeverityNote = lowSeverityNote;
    }
}
