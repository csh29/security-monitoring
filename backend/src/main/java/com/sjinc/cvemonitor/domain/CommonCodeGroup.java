package com.sjinc.cvemonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 공통코드관리 화면의 마스터(좌측 그룹 목록). 디테일인 {@link CommonCode}는 이 그룹의
 * 자연키(codeGroup)를 그대로 들고 있어서, 화면에서 그룹 하나를 선택하면 같은 codeGroup을
 * 가진 CommonCode만 우측 디테일 그리드에 조회된다.
 */
@Entity
@Table(name = "COMMON_CODE_MST")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CommonCodeGroup {

    /** 그룹을 식별하는 자연키(예: "ROLE"). 다른 화면의 select들이 CommonCode 조회 시 이 값으로 그룹을 지정한다. */
    @Id
    @Column(name = "code_group")
    private String codeGroup;

    @Column(name = "group_name", nullable = false)
    private String groupName;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    /** 사용여부. "Y" 또는 "N". */
    @Column(name = "use_yn", nullable = false)
    private String useYn;
}
