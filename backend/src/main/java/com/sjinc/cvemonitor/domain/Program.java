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

    /** 프로그램을 식별하는 자연키(예: "program-mng"). code 컬럼을 대체한다. */
    @Id
    @Column(name = "program_id")
    private String programId;

    /** 프로그램명(사이드바 메뉴·탭 제목에 그대로 보인다). */
    @Column(name = "program_nm", nullable = false)
    private String programNm;

    @Column(nullable = false)
    private String url;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    /** 사용여부. "Y" 또는 "N". */
    @Column(name = "use_yn", nullable = false)
    private String useYn;

    // ── 화면 공통 버튼 사용 여부("Y"/"N"). 기타1~5는 이름을 넣으면 그 이름으로 버튼이 생긴다. ──
    @Builder.Default
    @Column(name = "search_yn", nullable = false)
    private String searchYn = "N";
    @Builder.Default
    @Column(name = "new_yn", nullable = false)
    private String newYn = "N";
    @Builder.Default
    @Column(name = "save_yn", nullable = false)
    private String saveYn = "N";
    @Builder.Default
    @Column(name = "delete_yn", nullable = false)
    private String deleteYn = "N";
    @Builder.Default
    @Column(name = "reset_yn", nullable = false)
    private String resetYn = "N";
    @Column(name = "etc1_nm")
    private String etc1Nm;
    @Column(name = "etc2_nm")
    private String etc2Nm;
    @Column(name = "etc3_nm")
    private String etc3Nm;
    @Column(name = "etc4_nm")
    private String etc4Nm;
    @Column(name = "etc5_nm")
    private String etc5Nm;

    /** 이 프로그램이 그 버튼을 쓰는가. 기타 버튼은 이름이 입력돼 있으면 쓰는 것으로 본다. */
    public boolean uses(ProgramButton button) {
        return switch (button) {
            case SEARCH -> "Y".equals(searchYn);
            case NEW -> "Y".equals(newYn);
            case SAVE -> "Y".equals(saveYn);
            case DELETE -> "Y".equals(deleteYn);
            case RESET -> "Y".equals(resetYn);
            default -> buttonLabel(button) != null;
        };
    }

    /** 툴바에 보일 버튼 이름. 기타 버튼은 입력한 이름(비어 있으면 null), 나머지는 고정 이름. */
    public String buttonLabel(ProgramButton button) {
        String etc = switch (button) {
            case ETC1 -> etc1Nm;
            case ETC2 -> etc2Nm;
            case ETC3 -> etc3Nm;
            case ETC4 -> etc4Nm;
            case ETC5 -> etc5Nm;
            default -> button.getDefaultLabel();
        };
        return (etc == null || etc.isBlank()) ? null : etc.trim();
    }
}
