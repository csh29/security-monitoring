package com.sjinc.securitymonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 공통코드 마스터(그룹). 등록·수정·삭제는 공통코드마스터 관리 화면에서 하고, 공통코드 관리 화면은
 * 좌측에 조회만 한다. 디테일인 {@link ComCd}는 이 그룹의 자연키(codeGroup)를 그대로 들고
 * 있어서, 그룹 하나를 선택하면 같은 codeGroup을 가진 ComCd만 우측 디테일 그리드에 조회된다.
 */
@Entity
@Table(name = "COM_CD_MST")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ComCdGroup {

    /** 그룹을 식별하는 자연키(예: "ROLE"). 다른 화면의 select들이 ComCd 조회 시 이 값으로 그룹을 지정한다. */
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

    @Column(name = "remark")
    private String remark;
}
