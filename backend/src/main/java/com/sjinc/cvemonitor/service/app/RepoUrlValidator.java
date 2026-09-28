package com.sjinc.cvemonitor.service.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

/**
 * 앱 관리에 등록하려는 저장소 URL이 스캔해도 되는 주소인지 검사한다.
 *
 * <p>스캔은 이 URL을 그대로 clone하면서 {@code git.access.token}(GitLab PAT)을 붙이고, 받아온
 * pom.xml로 Maven을 실행한다. 즉 등록되는 URL은 "서버가 자격증명을 들고 찾아가서, 그쪽이 준
 * 빌드 파일을 실행하는 대상"이다. 임의 호스트를 허용하면 세 가지가 동시에 열린다 —
 * 공격자 서버로 PAT가 그대로 전송되고(자격증명 유출), 공격자가 만든 pom.xml의
 * {@code <repositories>}·build extension을 Maven이 그대로 타고, 내부망 주소를 넣으면 SSRF가 된다.
 *
 * <p>스캔 시점에는 이미 "앱 관리에 등록된 조합만 허용"으로 한 번 걸러지므로, 막아야 할 지점은
 * 등록(저장)하는 이 자리다. 등록 권한({@code app-management})이 있는 사용자를 신뢰하더라도,
 * 실수로 잘못된 URL을 넣는 것까지 막아주는 게 낫다.
 *
 * <p>Spring 없이 {@code new RepoUrlValidator(List.of(...))}로 만들 수 있어 단위 테스트가 된다.
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
