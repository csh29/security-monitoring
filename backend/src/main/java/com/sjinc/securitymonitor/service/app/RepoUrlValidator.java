package com.sjinc.securitymonitor.service.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

/**
 * 앱 관리에 등록하려는 저장소 URL이 스캔해도 되는 주소인지 등록 시점에 검사한다.
 * 서버는 이 URL에 Git 인증 정보를 붙여 clone하고 받아온 pom.xml로 Maven을 실행하므로,
 * 임의 호스트를 허용하면 자격증명 유출·악성 pom 실행·SSRF가 동시에 열린다.
 */
@Component
public class RepoUrlValidator {

    private final List<String> allowedHosts;

    public RepoUrlValidator(
            // 사내 GitLab 호스트. 다른 호스트를 쓰게 되면 application.properties에서
            // scan.allowed-repo-hosts=a.com,b.com 처럼 늘린다.
            @Value("#{'${scan.allowed-repo-hosts:git.sejung.co.kr}'.split(',')}") List<String> allowedHosts) {
        this.allowedHosts = allowedHosts.stream()
                .map(host -> host.trim().toLowerCase(Locale.ROOT))
                .filter(host -> !host.isEmpty())
                .toList();
    }

    /** 허용 호스트(소문자). Git 인증 정보도 이 호스트에만 붙인다(GitConfig). */
    public List<String> allowedHosts() {
        return allowedHosts;
    }

    /** 허용되지 않는 URL이면 {@link IllegalArgumentException}을 던진다. */
    public void validate(String repoUrl) {
        if (repoUrl == null || repoUrl.isBlank()) {
            throw new IllegalArgumentException("저장소 URL이 비어 있습니다.");
        }

        URI uri;
        try {
            uri = new URI(repoUrl.trim());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("저장소 URL 형식이 올바르지 않습니다: " + repoUrl);
        }

        // https만 허용한다. http는 PAT가 평문으로 나가고, ssh/git/file은 인증 방식과 접근 대상이
        // 달라서(특히 file://은 서버 로컬 디스크를 그대로 읽는다) 이 시스템의 스캔 대상이 아니다.
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("저장소 URL은 https만 허용합니다: " + repoUrl);
        }

        // https://git.sejung.co.kr@evil.com/... 처럼 사람 눈에는 허용 호스트로 보이지만 실제로는
        // 다른 호스트로 가는 형태를 애초에 거부한다(파싱은 정확하지만, 굳이 허용할 이유가 없다).
        if (uri.getUserInfo() != null) {
            throw new IllegalArgumentException("저장소 URL에 사용자 정보(@)를 포함할 수 없습니다: " + repoUrl);
        }

        String host = uri.getHost();
        if (host == null || !allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException(
                    "허용되지 않은 저장소 호스트입니다: " + host + " (허용: " + String.join(", ", allowedHosts) + ")");
        }
    }
}
