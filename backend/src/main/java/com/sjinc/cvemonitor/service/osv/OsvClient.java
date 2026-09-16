package com.sjinc.cvemonitor.service.osv;

import com.sjinc.cvemonitor.domain.MavenDependency;
import com.sjinc.cvemonitor.dto.osv.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

@Service
public class OsvClient {

    private final WebClient osvWebClient;

    public OsvClient(@Qualifier("osvWebClient") WebClient osvWebClient) {
        this.osvWebClient = osvWebClient;
    }

    /** 의존성 목록을 배치로 조회. 응답 순서는 dependencies 순서와 동일(인덱스 매칭). */
    public OsvBatchResponse queryBatch(List<MavenDependency> dependencies) {
        List<OsvQuery> queries = dependencies.stream()
                .map(dep -> new OsvQuery(new OsvPackage(dep.toOsvPackageName(), "Maven"), dep.version()))
                .toList();

        return osvWebClient.post()
                .uri("/v1/querybatch")
                .bodyValue(new OsvBatchRequest(queries))
                .retrieve()
                .bodyToMono(OsvBatchResponse.class)
                .block();
    }

    public OsvVulnDetail getVulnDetail(String vulnId) {
        return osvWebClient.get()
                .uri("/v1/vulns/{id}", vulnId)
                .retrieve()
                .bodyToMono(OsvVulnDetail.class)
                .block();
    }

    /**
     * 의존성 하나의 특정 버전을 단건 조회한다. 배치 조회와 달리 상세(OsvVulnDetail)를 바로
     * 돌려주므로 후속 {@code /v1/vulns/{id}} 호출이 필요 없다. AI가 제안한 fixed_version이나
     * OSV 후보 버전 "그 자체"에 또 다른 취약점이 있는지 재귀적으로 확인할 때 사용한다.
     */
    public List<OsvVulnDetail> queryVersion(String groupId, String artifactId, String version) {
        OsvQuery query = new OsvQuery(new OsvPackage(groupId + ":" + artifactId, "Maven"), version);
        OsvQueryResponse response = osvWebClient.post()
                .uri("/v1/query")
                .bodyValue(query)
                .retrieve()
                .bodyToMono(OsvQueryResponse.class)
                .block();
        return response != null && response.getVulns() != null ? response.getVulns() : List.of();
    }
}