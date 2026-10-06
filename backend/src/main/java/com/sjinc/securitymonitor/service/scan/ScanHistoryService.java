package com.sjinc.securitymonitor.service.scan;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.ScanHistory;
import com.sjinc.securitymonitor.dto.scan.ScanResult;
import com.sjinc.securitymonitor.repository.ScanHistoryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

/**
 * 스캔 이력(ScanHistory)의 기록과 조회. ScanOrchestrationService가 시작·성공·실패 시점에 부른다.
 *
 * <p>이력 기록은 부가 기능이라, 여기서 실패해도 스캔 자체를 실패시키지 않는다 — 스캔은 clone·Maven·NVD를
 * 다 돌린 비싼 작업이고 결과는 이미 Vulnerability에 저장된 뒤다. 대신 로그로 남긴다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ScanHistoryService {

    /** 이력 화면 한 번에 내려주는 최대 건수. 정기 스캔이 붙으면 앱 수 × 일수로 금방 늘어난다. */
    static final int MAX_ROWS = 500;

    private final ScanHistoryRepository scanHistoryRepository;

    /** @return 저장된 RUNNING 이력. 저장에 실패하면 null(이후 succeed/fail은 null을 받으면 아무것도 안 한다). */
    public ScanHistory start(App app, String requestedBy) {
        try {
            return scanHistoryRepository.save(ScanHistory.start(app, requestedBy));
        } catch (Exception e) {
            log.warn("[{}] 스캔 이력 시작 기록 실패(스캔은 계속 진행): {}", app.getSystemName(), e.toString());
            return null;
        }
    }

    public void succeed(ScanHistory history, ScanResult result, int newCount, int resolvedCount) {
        if (history == null) return;
        try {
            history.succeed(result.totalDependenciesScanned(), result.totalVulnerabilitiesFound(),
                    newCount, resolvedCount, result.failedCveCount());
            scanHistoryRepository.save(history);
        } catch (Exception e) {
            log.warn("[{}] 스캔 이력 완료 기록 실패: {}", history.getSystemName(), e.toString());
        }
    }

    public void fail(ScanHistory history, Exception cause) {
        if (history == null) return;
        try {
            history.fail(toErrorMessage(cause));
            scanHistoryRepository.save(history);
        } catch (Exception e) {
            log.warn("[{}] 스캔 이력 실패 기록 실패: {}", history.getSystemName(), e.toString());
        }
    }

    @Transactional(readOnly = true)
    public List<ScanHistory> getHistories(Long appId) {
        return scanHistoryRepository.findLatest(appId, PageRequest.of(0, MAX_ROWS));
    }

    /**
     * 스캔 전후 OPEN 키 집합으로 "이번 스캔에서 새로 OPEN이 된 건수"를 센다. 처음 발견된 건과, 해결됐다가 다시
     * 걸린 건이 모두 들어간다 — 담당자 입장에선 둘 다 "새로 조치할 것"이다. 키는 resolveMissingVulnerabilities와
     * 같은 "cveId|groupId:artifactId"다(CVE ID만으로 세면 같은 CVE가 다른 아티팩트에 새로 걸린 걸 놓친다).
     */
    static int countNewlyOpened(Set<String> openKeysBefore, Set<String> openKeysAfter) {
        return (int) openKeysAfter.stream().filter(key -> !openKeysBefore.contains(key)).count();
    }

    /**
     * 화면에 보일 오류 문구. 요청 자체가 잘못된 경우(IllegalArgumentException)만 메시지를 그대로 쓰고, 나머지는
     * 예외 종류만 남긴다 — Maven/JGit 예외 메시지에는 서버 임시 디렉터리 경로 같은 내부 정보가 섞인다
     * (ScanController.handleScanError와 같은 이유). 원인은 서버 로그에서 본다.
     */
    static String toErrorMessage(Exception cause) {
        if (cause instanceof IllegalArgumentException && cause.getMessage() != null) {
            return cause.getMessage();
        }
        return "스캔 도중 오류가 발생했습니다(" + cause.getClass().getSimpleName() + "). 서버 로그를 확인해주세요.";
    }
}
