package com.sjinc.securitymonitor.service.git;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * clone할 저장소 주소에 붙일 Git 인증 정보를 주소 앞부분(호스트·그룹)별 설정에서 경로 단위로 가장 길게 일치하는 것으로 고른다.
 * 일치가 없으면 인증 없이 clone한다 — 기본 토큰을 두지 않아 다른 호스트로 사내 토큰이 나가지 않는다.
 * 설정이 잘못되면 기동 때 실패시킨다(조용히 인증 없이 clone하면 원인을 찾기 어렵다).
 */
public class GitCredentialResolver {

    /** GitLab·GitHub는 토큰 인증에서 사용자 이름을 보지 않지만 비어 있으면 JGit이 인증을 보내지 않는다. 비었을 때 쓰는 값. */
    static final String DEFAULT_USERNAME = "oauth2";

    /** 설정 한 항목({@code git.credentials[n]}). */
    public record Entry(String urlPrefix, String username, String token) {
    }

    /** 고른 인증 정보. source는 로그용 설명(어느 항목을 썼는지 — 토큰은 넣지 않는다). */
    public record Credential(String username, String token, String source) {
        @Override
        public String toString() {
            return "Credential[" + source + "]";
        }
    }

    private final List<Entry> entries;
    private final List<String> allowedHosts;

    public GitCredentialResolver(List<Entry> entries, List<String> allowedHosts) {
        this.allowedHosts = allowedHosts.stream().map(h -> h.trim().toLowerCase(Locale.ROOT)).filter(h -> !h.isEmpty()).toList();
        this.entries = entries.stream().map(this::validated)
                .sorted(Comparator.comparingInt((Entry e) -> e.urlPrefix().length()).reversed())
                .toList();
        long distinct = this.entries.stream().map(Entry::urlPrefix).distinct().count();
        if (distinct != this.entries.size()) {
            // 같은 주소가 두 번이면 어느 토큰을 쓸지 설정 순서에 기대게 된다 — 복사해 늘리다 생기는 실수라 막는다.
            throw new IllegalStateException("git.credentials에 같은 url-prefix가 두 번 이상 있습니다.");
        }
    }

    public Optional<Credential> resolve(String repoUrl) {
        String url = normalize(repoUrl);
        for (Entry entry : entries) {
            if (url.equals(entry.urlPrefix()) || url.startsWith(entry.urlPrefix() + "/")) {
                return Optional.of(new Credential(username(entry), entry.token(), "git.credentials " + entry.urlPrefix()));
            }
        }
        return Optional.empty();
    }

    private Entry validated(Entry entry) {
        String prefix = entry.urlPrefix() == null ? "" : normalize(entry.urlPrefix());
        if (!prefix.startsWith("https://")) {
            throw new IllegalStateException("git.credentials의 url-prefix는 https 주소여야 합니다: " + entry.urlPrefix());
        }
        String host = host(prefix);
        if (host == null || !allowedHosts.contains(host)) {
            throw new IllegalStateException("git.credentials의 url-prefix 호스트가 scan.allowed-repo-hosts에 없습니다: " + entry.urlPrefix());
        }
        if (isBlank(entry.token())) {
            throw new IllegalStateException("git.credentials의 token이 비어 있습니다: " + entry.urlPrefix());
        }
        return new Entry(prefix, entry.username(), entry.token());
    }

    /** 앞뒤 공백·끝 슬래시를 뗀다. 대소문자는 무시한다 — 호스트는 원래 구분하지 않고, GitLab 경로도 구분하지 않고 찾아간다. */
    private static String normalize(String url) {
        String value = url == null ? "" : url.trim().toLowerCase(Locale.ROOT);
        while (value.endsWith("/")) value = value.substring(0, value.length() - 1);
        return value;
    }

    private static String host(String url) {
        try {
            String host = new URI(url).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static String username(Entry entry) {
        return isBlank(entry.username()) ? DEFAULT_USERNAME : entry.username().trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
