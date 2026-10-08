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

    /** 소스를 Git 저장소에서 받는다(라이브러리 스캔·코드 점검 모두). */
    public static final String SOURCE_GIT = "GIT";
    /**
     * 소스를 zip으로 올려 코드 점검만 한다 — Git으로 접근할 수 없는 앱(옛날 시스템 등). 저장소 URL·브랜치가 없고, 라이브러리 스캔은 할 수 없다
     * (업로드된 pom.xml로 Maven을 돌리면 플러그인·저장소가 서버에서 실행된다 — 스캔을 등록된 저장소로만 하는 것과 같은 이유).
     */
    public static final String SOURCE_UPLOAD = "UPLOAD";

    /** Git 앱만 있다. 업로드 앱은 null(스키마는 SchemaMigration이 nullable로 바꾼다). */
    @Column(name = "repo_url")
    private String repoUrl;

    @Column
    private String branch;

    /** 공통코드 APP_SOURCE 값(GIT/UPLOAD). 이 컬럼이 생기기 전 행은 null — Git 앱이다. */
    @Column(name = "source_type", length = 10)
    private String sourceType;

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

    /** zip 업로드로 코드 점검만 하는 앱인가. */
    public boolean isUploadSource() {
        return SOURCE_UPLOAD.equals(sourceType);
    }
}
