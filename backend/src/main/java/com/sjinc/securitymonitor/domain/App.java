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

/** 앱 관리 화면에 등록된 스캔 대상 앱(레포지토리 URL/브랜치/시스템명). */
@Entity
@Table(name = "apps")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class App {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "app_id")
    private Long id;

    @Column(name = "repo_url", nullable = false)
    private String repoUrl;

    @Column(nullable = false)
    private String branch;

    @Column(name = "system_name", nullable = false)
    private String systemName;

    @Column
    private String description;

    /**
     * 앱 담당자. 로그인 계정(User)에는 이메일이 없고, 담당자가 이 시스템 계정이 없는 개발자일 수도 있어서
     * User를 참조하지 않고 이름·이메일을 그대로 적는다. 이메일은 신규 취약점 알림 메일의 수신처로 쓸 값이다.
     * 기존 행이 있는 DB에 ddl-auto=update로 컬럼이 추가되므로 null을 허용한다.
     */
    @Column(name = "manager_name")
    private String managerName;

    @Column(name = "manager_email")
    private String managerEmail;
}
