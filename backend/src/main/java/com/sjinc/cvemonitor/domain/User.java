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
}
