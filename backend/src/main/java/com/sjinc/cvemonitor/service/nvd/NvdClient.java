package com.sjinc.cvemonitor.service.nvd;

import com.sjinc.cvemonitor.dto.nvd.NvdResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.util.retry.Retry;

import java.time.Duration;

/**
 * fileName       : NvdClient
 * author         : 최세훈
 * date           : 26. 9. 2.
 * description    : NVD API 통신 전담
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 26. 9. 2.        최세훈       최초 생성
 * 26. 9. 28.       최세훈       호출 간격 제어 + 재시도 + 타임아웃 추가
 */
@Service
@Slf4j
public class NvdClient {

    private final WebClient nvdWebClient;

    /**
     * 호출 사이 최소 간격(ms).
     *
     * <p>스캔은 CVE 건수만큼 이 API를 연속으로 부른다(100건이면 100회). NVD는 API 키가 있어도
     * 30초당 50회가 상한이라, 간격을 두지 않으면 수십 건째에서 반드시 429를 맞는다.
     * 30초/50회 = 600ms가 이론상 하한이라 여유를 둬서 700ms를 기본값으로 한다.
     */
    @Value("${nvd.api.min-interval-ms:700}")
    private long minIntervalMs;

    /** 한 건당 재시도 횟수. 여기까지 실패하면 그 CVE만 건너뛰고 스캔은 계속된다(호출부에서 처리). */
    @Value("${nvd.api.max-retries:3}")
    private long maxRetries;

    @Value("${nvd.api.timeout-seconds:20}")
    private long timeoutSeconds;

    /** 마지막 호출 시각. 스캔 루프가 단일 스레드라도 동시 스캔 가능성이 있어 동기화해서 지킨다. */
    private final Object throttleLock = new Object();
    private long lastCallAt;

    public NvdClient(@Qualifier("nvdWebClient") WebClient nvdWebClient) {
        this.nvdWebClient = nvdWebClient;
    }

    public NvdResponse getCveById(String cveId) {
        throttle();

        return nvdWebClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("cveId", cveId)
                        .build())
                .retrieve()
                .bodyToMono(NvdResponse.class)
                // timeout을 retryWhen보다 먼저 걸어야 재시도할 때마다 타임아웃이 새로 적용된다
                // (뒤에 걸면 전체 재시도를 합쳐서 하나의 타임아웃이 된다).
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .retryWhen(Retry.backoff(maxRetries, Duration.ofSeconds(2))
                        .filter(this::isRetryable)
                        // 기본 동작은 원인 예외를 RetryExhaustedException으로 감싸버려서, 호출부가
                        // "무엇 때문에 실패했는지" 로그에서 알아보기 어려워진다. 원래 예외를 그대로 던진다.
                        .onRetryExhaustedThrow((spec, signal) -> signal.failure())
                        .doBeforeRetry(signal -> log.warn("NVD 조회 재시도 {}회차 [{}]: {}",
                                signal.totalRetries() + 1, cveId, signal.failure().toString())))
                .block();
    }

    /**
     * 429(호출 한도 초과)와 5xx, 그리고 연결 자체가 실패한 경우만 재시도한다.
     * 404나 400은 다시 불러도 같은 답이라 재시도가 시간 낭비일 뿐이다.
     */
    private boolean isRetryable(Throwable throwable) {
        if (throwable instanceof WebClientResponseException e) {
            return e.getStatusCode().value() == 429 || e.getStatusCode().is5xxServerError();
        }
        return throwable instanceof WebClientRequestException || throwable instanceof java.util.concurrent.TimeoutException;
    }

    private void throttle() {
        synchronized (throttleLock) {
            long waitMs = lastCallAt + minIntervalMs - System.currentTimeMillis();
            if (waitMs > 0) {
                try {
                    Thread.sleep(waitMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("NVD 호출 대기 중 인터럽트됨", e);
                }
            }
            lastCallAt = System.currentTimeMillis();
        }
    }
}
