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
}
