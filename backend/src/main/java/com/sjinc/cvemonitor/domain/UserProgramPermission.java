package com.sjinc.cvemonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** 특정 사용자가 특정 프로그램(추가 메뉴)에 접근할 수 있음과, 그 화면에서 쓸 수 있는 공통 버튼을 나타내는 권한 레코드. */
@Entity
@Table(name = "user_program_permissions",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "program_id"}))
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserProgramPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "program_id", referencedColumnName = "program_id", nullable = false)
    private Program program;

    // ── 이 사용자에게 허용된 화면 공통 버튼("Y"/"N"). 프로그램이 쓰는 버튼 중 여기서 Y인 것만 툴바에 보인다. ──
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
    @Builder.Default
    @Column(name = "etc1_yn", nullable = false)
    private String etc1Yn = "N";
    @Builder.Default
    @Column(name = "etc2_yn", nullable = false)
    private String etc2Yn = "N";
    @Builder.Default
    @Column(name = "etc3_yn", nullable = false)
    private String etc3Yn = "N";
    @Builder.Default
    @Column(name = "etc4_yn", nullable = false)
    private String etc4Yn = "N";
    @Builder.Default
    @Column(name = "etc5_yn", nullable = false)
    private String etc5Yn = "N";

    public boolean allows(ProgramButton button) {
        String yn = switch (button) {
            case SEARCH -> searchYn;
            case NEW -> newYn;
            case SAVE -> saveYn;
            case DELETE -> deleteYn;
            case RESET -> resetYn;
            case ETC1 -> etc1Yn;
            case ETC2 -> etc2Yn;
            case ETC3 -> etc3Yn;
            case ETC4 -> etc4Yn;
            case ETC5 -> etc5Yn;
        };
        return "Y".equals(yn);
    }
}
