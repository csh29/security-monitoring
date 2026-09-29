package com.sjinc.cvemonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** 화면마다 하드코딩되던 select 옵션(역할, 심각도, 처리상태 등)을 공통코드 관리 화면에서 관리하기 위한 코드 한 줄. */
@Entity
@Table(name = "COM_CD_DTL")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ComCd {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "code_id")
    private Long id;

    /** 코드를 묶는 그룹(예: "ROLE", "SEVERITY", "VULN_STATUS"). 화면에서는 이 값으로 select를 채운다. */
    @Column(name = "code_group", nullable = false)
    private String codeGroup;

    /** select의 option value로 쓰이는 실제 코드값(예: "OPEN"). */
    @Column(name = "code_value", nullable = false)
    private String codeValue;

    /** select에 보여줄 라벨(예: "미해결"). */
    @Column(name = "code_name", nullable = false)
    private String codeName;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    /** 사용여부. "Y" 또는 "N" — "N"인 코드는 select에서 제외된다. */
    @Column(name = "use_yn", nullable = false)
    private String useYn;

    @Column(name = "remark")
    private String remark;
}
