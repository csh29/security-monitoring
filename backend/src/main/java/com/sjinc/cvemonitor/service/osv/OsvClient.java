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
}