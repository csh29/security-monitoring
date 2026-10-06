package com.sjinc.securitymonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * fix-plan이 pom.xml에서 바꾼 버전 값 하나. 예전엔 "무엇을 몇에서 몇으로 올리는가"가 reasoning 문장 안에만
 * 있어서, 업그레이드 영향 분석이 그 문장을 다시 해석해야 했다(경로를 AI가 재구성하다 틀린 것과 같은 위험).
 * AI가 fix-plan과 같은 응답에서 구조화해 내고, 점프 폭(jump)은 자바가 계산해 붙인다.
 */
@Entity
@Table(name = "fix_plan_changes")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class FixPlanChange {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "fix_plan_change_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "fix_plan_id", nullable = false)
    private FixPlan fixPlan;

    /** AI가 낸 순서. 화면에 수정안과 같은 순서로 보여주기 위함. */
    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    /**
     * 버전이 실제로 바뀌는 라이브러리의 groupId:artifactId. parent 업그레이드면 parent 좌표, BOM import면 BOM 좌표,
     * 프로퍼티 override면 그 프로퍼티가 관리하는 대표 아티팩트 좌표다.
     */
    @Column(nullable = false)
    private String coordinate;

    /** 프로퍼티 override로 바꿨을 때만 그 프로퍼티 이름(예: netty.version). 아니면 null. */
    @Column(name = "property_name")
    private String propertyName;

    @Column(name = "from_version", nullable = false)
    private String fromVersion;

    @Column(name = "to_version", nullable = false)
    private String toVersion;

    /** PARENT / BOM / PROPERTY / DIRECT — pom.xml의 어느 자리를 고쳤는가. */
    @Column(nullable = false, length = 20)
    private String via;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private VersionJump jump;
}
