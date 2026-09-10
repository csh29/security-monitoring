package com.sjinc.cvemonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** 사이드바 고정 메뉴(홈/취약점 관리/취약점 조회/리포트) 외에, 권한을 가진 사용자에게만 노출되는 추가 프로그램(메뉴). */
@Entity
@Table(name = "programs")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Program {

    /** 프로그램을 식별하는 자연키(예: "program-management"). code 컬럼을 대체한다. */
    @Id
    @Column(name = "program_id")
    private String programId;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String url;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    /** 사용여부. "Y" 또는 "N". */
    @Column(name = "use_yn", nullable = false)
    private String useYn;
}
