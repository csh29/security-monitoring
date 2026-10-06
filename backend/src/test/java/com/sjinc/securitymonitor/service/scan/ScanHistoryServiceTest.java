package com.sjinc.securitymonitor.service.scan;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.ScanHistory;
import com.sjinc.securitymonitor.dto.scan.ScanResult;
import com.sjinc.securitymonitor.repository.ScanHistoryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScanHistoryServiceTest {

    private ScanHistoryRepository repository;
    private ScanHistoryService service;

    private final App app = App.builder()
            .id(1L).repoUrl("https://git.sejung.co.kr/crm/back.git").branch("dev").systemName("CRM_BACK").build();

    @BeforeEach
    void setUp() {
        repository = mock(ScanHistoryRepository.class);
        when(repository.save(any(ScanHistory.class))).thenAnswer(invocation -> invocation.getArgument(0));
        service = new ScanHistoryService(repository);
    }

    @Test
    void 스캔_전엔_OPEN이_아니던_키만_신규로_센다() {
        Set<String> before = Set.of("CVE-1|g:a", "CVE-2|g:a");
        Set<String> after = Set.of("CVE-2|g:a", "CVE-3|g:a", "CVE-1|g:b");

        // CVE-3은 처음 발견, CVE-1|g:b는 같은 CVE가 다른 아티팩트에 새로 걸린 것 — 둘 다 신규다.
        assertThat(ScanHistoryService.countNewlyOpened(before, after)).isEqualTo(2);
        assertThat(ScanHistoryService.countNewlyOpened(after, after)).isZero();
    }

    @Test
    void 시작하면_앱_정보를_복사한_RUNNING_이력이_저장된다() {
        ScanHistory history = service.start(app, "admin");

        assertThat(history.getStatus()).isEqualTo(ScanHistory.RUNNING);
        assertThat(history.getAppId()).isEqualTo(1L);
        assertThat(history.getSystemName()).isEqualTo("CRM_BACK");
        assertThat(history.getRequestedBy()).isEqualTo("admin");
        assertThat(history.getFinishedAt()).isNull();
    }

    @Test
    void 성공하면_건수와_종료시각이_채워진다() {
        ScanHistory history = service.start(app, "admin");
        ScanResult result = new ScanResult(app.getRepoUrl(), "dev", "CRM_BACK", 120, 7, 1, List.of());

        service.succeed(history, result, 3, 2);

        assertThat(history.getStatus()).isEqualTo(ScanHistory.SUCCESS);
        assertThat(history.getDependencyCount()).isEqualTo(120);
        assertThat(history.getVulnerabilityCount()).isEqualTo(7);
        assertThat(history.getNewCount()).isEqualTo(3);
        assertThat(history.getResolvedCount()).isEqualTo(2);
        assertThat(history.getFailedCveCount()).isEqualTo(1);
        assertThat(history.getFinishedAt()).isNotNull();
    }

    @Test
    void 실패_문구에는_내부_예외_메시지를_남기지_않는다() {
        ScanHistory history = service.start(app, "admin");

        service.fail(history, new IllegalStateException("/tmp/scan-123/Temp/pom.xml 읽기 실패"));

        assertThat(history.getStatus()).isEqualTo(ScanHistory.FAILED);
        assertThat(history.getErrorMessage()).contains("IllegalStateException").doesNotContain("Temp");
    }

    @Test
    void 잘못된_요청은_사유를_그대로_남긴다() {
        assertThat(ScanHistoryService.toErrorMessage(new IllegalArgumentException("pom.xml이 없습니다")))
                .isEqualTo("pom.xml이 없습니다");
    }

    @Test
    void 이력_저장이_실패해도_스캔을_막지_않는다() {
        when(repository.save(any(ScanHistory.class))).thenThrow(new RuntimeException("DB 잠금"));

        ScanHistory history = service.start(app, "admin");

        assertThat(history).isNull();
        // null 이력으로 불러도 예외 없이 지나간다.
        service.fail(null, new RuntimeException("스캔 실패"));
    }
}
