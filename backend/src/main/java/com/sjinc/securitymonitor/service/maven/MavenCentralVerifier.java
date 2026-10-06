package com.sjinc.securitymonitor.service.maven;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * AI(NVD/OSV 기반)가 제안한 수정 버전이 실제로 Maven Central에 존재하는 아티팩트인지 확인한다.
 *
 * <p>NVD의 configurations나 OSV의 fixed 이벤트가 알려주는 버전이 항상 공개 저장소에 존재하는 건
 * 아니다 — Spring/VMware 계열은 OSS 공개 지원이 끝나면 그 이후 버전이 상용(commercial) 전용
 * 저장소로만 나가고, 일부 라이브러리는 groupId 자체가 바뀐 뒤에 새 버전이 나오기도 한다(예:
 * software.amazon.ion:ion-java -> com.amazon.ion:ion-java). 이런 값을 그대로 fixedVersion에
 * 저장하면 fix-plan이 존재하지 않는 버전으로 pom.xml을 고쳐서 빌드를 깨뜨리게 된다.
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
     *
     * <p>네트워크 오류 등으로 확인 자체에 실패하면 true를 반환한다 — "확인 불가"와 "존재하지 않음"을
     * 구분하지 못하면, Maven Central 접속이 잠깐 끊긴 것만으로도 멀쩡한 버전이 전부 제거돼 버리는
     * 더 나쁜 상황이 생기기 때문이다(오탐으로 데이터를 지우는 것보다 검증을 건너뛰는 게 안전하다).
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
