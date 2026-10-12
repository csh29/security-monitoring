package com.sjinc.securitymonitor.domain;

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

/** 테이블명을 "user"로 두면 H2 등 다수 DB의 예약어와 충돌해서 DDL이 깨지므로 "users"로 분리. */
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    /** 사용자명(화면 표시용 이름). 로그인 아이디는 username이다. */
    @Column(name = "user_nm", nullable = false)
    private String userNm;

    @Column(nullable = false)
    private String password;

    /** "ROLE_" 접두어 없이 저장 (예: "ADMIN", "USER"). Spring Security의 roles()가 접두어를 붙여준다. */
    @Column(nullable = false)
    private String role;

    /** 사용여부(Y/N). N이면 로그인할 수 없다. 기존 행은 컬럼 기본값 Y로 채워진다. */
    @Builder.Default
    @Column(name = "use_yn", nullable = false, columnDefinition = "varchar(1) default 'Y' not null")
    private String useYn = "Y";

    public boolean isActive() {
        return !"N".equals(useYn);
    }

    /** 본인 비밀번호 변경(UserService.changeMyPassword). 인코딩된 값을 받는다. */
    public void changePassword(String encodedPassword) {
        this.password = encodedPassword;
    }
}
