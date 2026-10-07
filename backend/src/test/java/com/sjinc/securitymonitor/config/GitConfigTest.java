package com.sjinc.securitymonitor.config;

import com.sjinc.securitymonitor.service.app.RepoUrlValidator;
import com.sjinc.securitymonitor.service.git.GitCredentialResolver;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitConfigTest {

    private final RepoUrlValidator validator = new RepoUrlValidator(List.of("git.sejung.co.kr"));

    @Test
    void 설정_파일의_git_credentials_목록을_읽는다() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("git.credentials[0].url-prefix", "https://git.sejung.co.kr/crm/")
                .withProperty("git.credentials[0].username", "crm-bot")
                .withProperty("git.credentials[0].token", "crm-token")
                .withProperty("git.credentials[1].url-prefix", "https://git.sejung.co.kr/erp/")
                .withProperty("git.credentials[1].token", "erp-token");

        GitCredentialResolver resolver = new GitConfig().gitCredentialResolver(env, validator);

        assertThat(resolver.resolve("https://git.sejung.co.kr/crm/a.git")).get()
                .extracting(GitCredentialResolver.Credential::username, GitCredentialResolver.Credential::token)
                .containsExactly("crm-bot", "crm-token");
        assertThat(resolver.resolve("https://git.sejung.co.kr/erp/b.git")).get()
                .extracting(GitCredentialResolver.Credential::token).isEqualTo("erp-token");
    }

    @Test
    void 예전_단일_설정이_남아_있으면_옮기라고_기동을_멈춘다() {
        MockEnvironment env = new MockEnvironment().withProperty("git.access.token", "old-token");

        assertThatThrownBy(() -> new GitConfig().gitCredentialResolver(env, validator))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("git.credentials");
    }

    @Test
    void 설정이_없으면_인증_없이_clone한다() {
        assertThat(new GitConfig().gitCredentialResolver(new MockEnvironment(), validator)
                .resolve("https://git.sejung.co.kr/a/b.git")).isEmpty();
    }
}
