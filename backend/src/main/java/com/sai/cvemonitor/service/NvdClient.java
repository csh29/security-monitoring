package com.sai.cvemonitor.service;

import com.sai.cvemonitor.dto.NvdResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * fileName       : NvdClient
 * author         : 최세훈
 * date           : 26. 9. 2.
 * description    : NVD API 통신 전담
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 26. 9. 2.        최세훈       최초 생성
 */
@Service
public class NvdClient {

    private final WebClient nvdWebClient;

    public NvdClient(@Qualifier("nvdWebClient") WebClient nvdWebClient) {
        this.nvdWebClient = nvdWebClient;
    }

    public NvdResponse getRecentCves(String lastModStart, String lastModEnd) {
        return nvdWebClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("lastModStartDate", lastModStart)
                        .queryParam("lastModEndDate", lastModEnd)
                        .build())
                .retrieve()
                .bodyToMono(NvdResponse.class)
                .block();
    }
}
