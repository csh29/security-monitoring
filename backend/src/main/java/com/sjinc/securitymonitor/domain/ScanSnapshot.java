package com.sjinc.securitymonitor.domain;

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

/**
 * 스캔 시점의 pom.xml/dependency:tree 원문 스냅샷. 스캔이 끝나면 clone 디렉터리는 지워지므로,
 * fix-plan 배치가 나중에 참고할 수 있도록 앱당 최신 스냅샷 하나만 여기 남겨둔다.
 */
@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanSnapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "app_id", referencedColumnName = "app_id", unique = true)
    private App app;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String pomXml;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String dependencyTree;

    /**
     * 소스에서 뽑은 import·설정 키 목록(SourceUsage JSON). 업그레이드 영향 분석의 breaking change가 우리 코드에 해당하는지
     * 조회 시점에 서버 안에서 대조한다(CodeUsageMatcher). null이면 이 기능이 생기기 전 스냅샷이거나 추출에 실패한 것이다.
     */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String sourceUsageJson;

    private LocalDateTime scannedAt;

    /** null이면 아직 이 스냅샷 기준으로 fix-plan을 만든 적이 없다는 뜻. */
    private LocalDateTime fixPlanGeneratedAt;

    public void updateSnapshot(String pomXml, String dependencyTree, String sourceUsageJson) {
        this.pomXml = pomXml;
        this.dependencyTree = dependencyTree;
        this.sourceUsageJson = sourceUsageJson;
        this.scannedAt = LocalDateTime.now();
    }

    public void markFixPlanGenerated() {
        this.fixPlanGeneratedAt = LocalDateTime.now();
    }
}
