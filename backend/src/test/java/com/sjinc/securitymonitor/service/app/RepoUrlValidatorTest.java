package com.sjinc.securitymonitor.service.app;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RepoUrlValidatorTest {

    private final RepoUrlValidator validator = new RepoUrlValidator(List.of("git.sejung.co.kr"));

    @Test
    void 허용된_호스트의_https_주소는_통과한다() {
        assertThatCode(() -> validator.validate("https://git.sejung.co.kr/crm/back.git"))
                .doesNotThrowAnyException();
    }

    @Test
    void 대소문자가_달라도_같은_호스트로_본다() {
        assertThatCode(() -> validator.validate("https://GIT.Sejung.CO.KR/crm/back.git"))
                .doesNotThrowAnyException();
    }

    @Test
    void 허용목록에_없는_호스트는_거부한다() {
        assertThatThrownBy(() -> validator.validate("https://evil.example.com/x.git"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("허용되지 않은 저장소 호스트");
    }

    /**
     * 허용 호스트 이름이 경로나 서브도메인 위치에 들어간 형태를 "포함"으로 느슨하게 비교하면
     * 통과해버린다. 호스트는 정확히 일치해야 한다.
     */
    @Test
    void 허용_호스트_이름이_다른_자리에_들어간_주소는_거부한다() {
        assertThatThrownBy(() -> validator.validate("https://evil.example.com/git.sejung.co.kr/x.git"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> validator.validate("https://git.sejung.co.kr.evil.example.com/x.git"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** https://허용호스트@실제목적지 — 사람 눈에는 허용 호스트로 보이지만 실제로는 다른 곳으로 간다. */
    @Test
    void 사용자정보가_붙은_주소는_거부한다() {
        assertThatThrownBy(() -> validator.validate("https://git.sejung.co.kr@evil.example.com/x.git"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("사용자 정보");
    }

    /** http는 clone 과정에서 PAT가 평문으로 나간다. */
    @Test
    void http는_거부한다() {
        assertThatThrownBy(() -> validator.validate("http://git.sejung.co.kr/crm/back.git"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
    }

    /** file://은 서버 로컬 디스크를 그대로 clone 대상으로 삼는다. */
    @Test
    void file과_ssh_스킴은_거부한다() {
        assertThatThrownBy(() -> validator.validate("file:///C:/secret"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> validator.validate("ssh://git@git.sejung.co.kr/crm/back.git"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 비어있거나_형식이_깨진_주소는_거부한다() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> validator.validate("   "))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> validator.validate("https://git.sejung.co.kr/ 공백"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
