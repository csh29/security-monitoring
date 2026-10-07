package com.sjinc.securitymonitor.service.git;

import com.sjinc.securitymonitor.service.git.GitCredentialResolver.Credential;
import com.sjinc.securitymonitor.service.git.GitCredentialResolver.Entry;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitCredentialResolverTest {

    private static final List<String> HOSTS = List.of("git.sejung.co.kr");

    private static Optional<String> tokenFor(GitCredentialResolver resolver, String url) {
        return resolver.resolve(url).map(Credential::token);
    }

    @Test
    void 가장_길게_일치하는_항목을_쓴다() {
        GitCredentialResolver resolver = new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr/", "u", "host-token"),
                new Entry("https://git.sejung.co.kr/crm/", "u", "crm-token")), HOSTS);

        assertThat(tokenFor(resolver, "https://git.sejung.co.kr/crm/crm-back.git")).contains("crm-token");
        assertThat(tokenFor(resolver, "https://git.sejung.co.kr/erp/erp-back.git")).contains("host-token");
    }

    @Test
    void 경로_단위로만_일치한다() {
        GitCredentialResolver resolver = new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr/crm", "u", "crm-token")), HOSTS);

        assertThat(tokenFor(resolver, "https://git.sejung.co.kr/crm/app.git")).contains("crm-token");
        assertThat(tokenFor(resolver, "https://git.sejung.co.kr/crm2/app.git")).isEmpty();
    }

    @Test
    void 대소문자와_끝_슬래시는_무시한다() {
        GitCredentialResolver resolver = new GitCredentialResolver(List.of(
                new Entry(" https://Git.Sejung.co.kr/CRM/ ", "u", "crm-token")), HOSTS);

        assertThat(tokenFor(resolver, "https://git.sejung.co.kr/crm/App.git")).contains("crm-token");
    }

    @Test
    void 호스트_주소_항목이_서버_전체_토큰_역할을_한다() {
        GitCredentialResolver resolver = new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr", "me", "host-token")), List.of("git.sejung.co.kr", "github.com"));

        assertThat(tokenFor(resolver, "https://git.sejung.co.kr/any/repo.git")).contains("host-token");
        // 다른 허용 호스트에는 붙이지 않는다 — 항목이 없는 호스트는 인증 없이.
        assertThat(tokenFor(resolver, "https://github.com/a/b.git")).isEmpty();
        assertThat(tokenFor(resolver, "https://git.sejung.co.kr.evil.com/a/b.git")).isEmpty();
    }

    @Test
    void 아무_설정도_없으면_인증_없이_clone한다() {
        assertThat(new GitCredentialResolver(List.of(), HOSTS).resolve("https://git.sejung.co.kr/a/b.git")).isEmpty();
    }

    @Test
    void 사용자_이름이_비면_기본_이름을_쓴다() {
        GitCredentialResolver resolver = new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr/crm", null, "t")), HOSTS);

        assertThat(resolver.resolve("https://git.sejung.co.kr/crm/a.git")).get()
                .extracting(Credential::username).isEqualTo(GitCredentialResolver.DEFAULT_USERNAME);
    }

    @Test
    void 로그용_문자열에_토큰이_들어가지_않는다() {
        GitCredentialResolver resolver = new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr/crm", "u", "secret-token")), HOSTS);

        Credential credential = resolver.resolve("https://git.sejung.co.kr/crm/a.git").orElseThrow();
        assertThat(credential.toString()).doesNotContain("secret-token");
        assertThat(credential.source()).doesNotContain("secret-token");
    }

    @Test
    void 잘못된_설정은_기동_때_실패한다() {
        assertThatThrownBy(() -> new GitCredentialResolver(List.of(
                new Entry("http://git.sejung.co.kr/crm", "u", "t")), HOSTS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("https");
        assertThatThrownBy(() -> new GitCredentialResolver(List.of(
                new Entry("https://evil.example.com/crm", "u", "t")), HOSTS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("allowed-repo-hosts");
        assertThatThrownBy(() -> new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr/crm", "u", " ")), HOSTS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("token");
        assertThatThrownBy(() -> new GitCredentialResolver(List.of(
                new Entry("https://git.sejung.co.kr/crm/", "u", "a"), new Entry("https://git.sejung.co.kr/CRM", "u", "b")), HOSTS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("같은 url-prefix");
    }
}
