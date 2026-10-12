package com.sjinc.securitymonitor.service.maven;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * NVD/OSV가 알려준 수정 버전이 실제로 Maven Central에 존재하는지 확인한다.
 * 상용 전용 릴리스나 groupId 변경 때문에 공개 저장소에 없는 버전이 있어, 그대로 쓰면 fix-plan이 빌드를 깨뜨린다.
 */
@Slf4j
@Service
public class MavenCentralVerifier {

    private final WebClient mavenCentralWebClient;

    public MavenCentralVerifier(@Qualifier("mavenCentralWebClient") WebClient mavenCentralWebClient) {
        this.mavenCentralWebClient = mavenCentralWebClient;
    }

    /**
     * groupId:artifactId:version 조합이 Maven Central에 실제로 존재하면 true.
     * 확인 자체에 실패해도 true다 — 접속이 잠깐 끊긴 것만으로 멀쩡한 버전을 지우는 것보다 검증을 건너뛰는 게 안전하다.
     */
    public boolean exists(String groupId, String artifactId, String version) {
        if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank()
                || version == null || version.isBlank()) {
            return true;
        }

        String path = groupId.replace('.', '/');
        String uri = "/%s/%s/%s/%s-%s.jar".formatted(path, artifactId, version, artifactId, version);

        try {
            Boolean found = mavenCentralWebClient.head()
                    .uri(uri)
                    .exchangeToMono(response -> Mono.just(response.statusCode().is2xxSuccessful()))
                    .block();
            return Boolean.TRUE.equals(found);
        } catch (Exception e) {
            log.warn("Maven Central 확인 실패({}:{}:{}), 검증을 건너뛰고 통과 처리: {}",
                    groupId, artifactId, version, e.getMessage());
            return true;
        }
    }
}
