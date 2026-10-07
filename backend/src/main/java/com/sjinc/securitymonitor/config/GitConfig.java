package com.sjinc.securitymonitor.config;

import com.sjinc.securitymonitor.service.app.RepoUrlValidator;
import com.sjinc.securitymonitor.service.git.GitCredentialResolver;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.List;

@Configuration
public class GitConfig {

    /**
     * 저장소 주소별 Git 인증 정보 {@code git.credentials[n].url-prefix/username/token}. 없으면 모든 저장소를 인증 없이 clone한다.
     * 허용 호스트는 앱 등록 검사와 같은 목록을 쓴다(RepoUrlValidator) — 두 곳이 따로 읽으면 한쪽만 바뀐다.
     */
    @Bean
    public GitCredentialResolver gitCredentialResolver(Environment environment, RepoUrlValidator repoUrlValidator) {
        if (environment.containsProperty("git.access.token") || environment.containsProperty("git.user.name")) {
            // 예전 단일 설정이 남아 있으면 조용히 무시되어 "인증 없이 clone → 저장소 없음"으로 실패한다. 옮기라고 알려주고 기동을 멈춘다.
            throw new IllegalStateException("git.access.token / git.user.name은 더 이상 쓰지 않습니다. "
                    + "git.credentials[0].url-prefix=https://<호스트>/ 항목의 username/token으로 옮기세요.");
        }
        List<GitCredentialResolver.Entry> entries = Binder.get(environment)
                .bind("git.credentials", Bindable.listOf(GitCredentialResolver.Entry.class))
                .orElse(List.of());
        return new GitCredentialResolver(entries, repoUrlValidator.allowedHosts());
    }
}
