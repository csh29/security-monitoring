package com.sjinc.securitymonitor.service.securecode;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeScan;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeApplyResult;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeScanResult;
import com.sjinc.securitymonitor.dto.securecode.SemgrepReport;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.SecureCodeScanRepository;
import com.sjinc.securitymonitor.service.git.GitCloneService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * 시큐어코딩 점검 1회를 처음부터 끝까지 잇는다: 등록 확인 → clone → Semgrep → 코드 조각·지문 → 기존 탐지와 비교·저장 → 이력.
 *
 * <p>라이브러리 스캔(ScanOrchestrationService)과 서로 부르지 않는다. 공유하는 것은 앱 등록과 clone뿐이다 — 한쪽이 실패하거나
 * 바뀌어도 다른 쪽에 영향이 없게 하기 위함이다. AI는 쓰지 않는다(1단계).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecureCodeScanService {

    static final int MAX_HISTORY_ROWS = 500;

    private final AppRepository appRepository;
    private final SecureCodeScanRepository scanRepository;
    private final SecureCodeFindingService findingService;
    private final GitCloneService gitCloneService;
    private final SemgrepRunner semgrepRunner;
    private final ObjectMapper objectMapper;

    /**
     * 한 번에 하나만 돈다. Semgrep은 메모리를 많이 쓰고, 여러 개가 동시에 돌면 사용자 홈의 Semgrep 설정 파일
     * (~/.semgrep/settings.yml)을 같이 쓰다 PermissionError로 실패한다(규칙 테스트 중 실제로 났다).
     */
    private final ReentrantLock scanLock = new ReentrantLock();

    @Value("${git.access.token}")
    private String gitAccessToken;

    @Value("${git.user.name}")
    private String gitUserName;

    /** 규칙 폴더. 서버를 backend/에서 띄우는 기준(ai.assessor.script와 같은 방식). */
    @Value("${securecode.rules-dir:../securecode/rules}")
    private String rulesDir;

    /** MyBatis ${} 연계 추적의 시스템별 프레임워크 규칙(TraceRules). 규칙 폴더 밖에 둔다 — 안에 두면 Semgrep이 규칙으로 읽는다. */
    @Value("${securecode.trace-rules:../securecode/trace-rules.yml}")
    private String traceRulesFile;

    /**
     * appId로만 받는다 — 앱 관리에 등록된 저장소만 점검한다(임의 URL clone은 토큰 유출·SSRF 위험, 라이브러리 스캔과 같은 이유).
     *
     * @param requestedBy 점검을 실행한 로그인 아이디(이력에 남긴다)
     */
    public SecureCodeScanResult scan(Long appId, String requestedBy) throws Exception {
        if (!scanLock.tryLock()) {
            throw SecureCodeScanException.busy();
        }
        try {
            App app = appRepository.findById(appId)
                    .orElseThrow(() -> new IllegalArgumentException("앱 관리에 등록되지 않은 앱입니다: appId=" + appId));
            SecureCodeScan history = startHistory(app, requestedBy);
            try {
                return run(app, history);
            } catch (Exception e) {
                failHistory(history, e);
                throw e;
            }
        } finally {
            scanLock.unlock();
        }
    }

    @Transactional(readOnly = true)
    public List<SecureCodeScan> getHistories(Long appId) {
        return scanRepository.findLatest(appId, PageRequest.of(0, MAX_HISTORY_ROWS));
    }

    private SecureCodeScanResult run(App app, SecureCodeScan history) throws Exception {
        // 규칙을 clone보다 먼저 읽는다 — 규칙 폴더가 잘못됐으면 clone할 필요도 없다.
        Path rules = Path.of(rulesDir);
        RuleSetLoader.RuleSet ruleSet = new RuleSetLoader().load(rules, List.of(Path.of(traceRulesFile)));
        TraceRules traceRules = loadTraceRules();

        File projectDir = gitCloneService.cloneRepository(app.getRepoUrl(), app.getBranch(), gitUserName, gitAccessToken);
        try {
            SemgrepReport report = new SemgrepReportParser(objectMapper)
                    .parse(semgrepRunner.run(projectDir.toPath(), rules));
            List<DetectedFinding> detected = new SecureCodeSnippetBuilder(projectDir.toPath()).build(report.matches());
            TraceOutcome trace = traceFindings(app, projectDir.toPath(), detected, traceRules);
            detected = trace.findings();

            SecureCodeApplyResult applied = findingService.applyScan(
                    app.getId(), detected, report.failedFiles(), ruleSet.ruleIds());

            log.info("[{}] 코드 점검 완료: 파일 {}개, 탐지 {}건(신규 {}, 해결 {}), 분석 실패 파일 {}개",
                    app.getSystemName(), report.scannedFileCount(), detected.size(),
                    applied.newCount(), applied.resolvedCount(), report.failedFiles().size());
            if (!report.failedFiles().isEmpty()) {
                log.warn("[{}] Semgrep이 끝까지 보지 못한 파일: {}", app.getSystemName(), report.failedFiles());
            }

            succeedHistory(history, report, detected.size(), applied, ruleSet.version());
            return new SecureCodeScanResult(app.getSystemName(), report.scannedFileCount(), detected.size(),
                    applied.newCount(), applied.resolvedCount(), report.failedFiles().size(), trace.note());
        } finally {
            gitCloneService.cleanup(projectDir);
        }
    }

    /** 연계 추적 결과. note는 화면 알림에 덧붙일 문구(문제가 없으면 null). */
    private record TraceOutcome(List<DetectedFinding> findings, String note) {
    }

    private TraceRules loadTraceRules() throws IOException {
        Path file = Path.of(traceRulesFile);
        if (!Files.isRegularFile(file)) {
            log.warn("연계 추적 규칙 파일이 없습니다({}) — 세션 덮어쓰기를 모르므로 해당 ${…}는 클라이언트 값으로 판정됩니다.",
                    file.toAbsolutePath().normalize());
        }
        return TraceRules.load(file);
    }

    /**
     * 출처를 따라갈 수 있는 탐지에 연계 추적 판정·근거를 붙이고 등급을 다시 매긴다.
     * <ul>
     *   <li>MyBatis ${}(MybatisDollarTracer) — 값이 클라이언트에서 오는지, 서버가 세팅하는지, 공통 실행 경로로 우회되는지</li>
     *   <li>위험 호출 지점(SinkTracer) — SSRF 변수 주소·명령 실행·다운로드 경로·업로드 저장·문자열 연결 SQL에 들어가는 값의 출처</li>
     * </ul>
     * Java 구문 분석은 한 번만 하고 둘이 같은 색인을 쓴다. 추적은 부가 판정이라 실패해도 점검을 실패시키지 않는다 — 대신 Semgrep 등급을
     * 그대로 두고(모르면 위험한 쪽), 그 사실을 화면 알림으로 올린다. "추적이 돌아서 안전해 보이는 것"과 "추적을 못 한 것"을 구분할 수 있어야 한다.
     */
    private TraceOutcome traceFindings(App app, Path projectDir, List<DetectedFinding> detected, TraceRules traceRules) {
        boolean hasDollar = detected.stream().anyMatch(f -> DollarTraceMerger.RULE_ID.equals(f.ruleId()));
        boolean hasSink = detected.stream().anyMatch(f -> SinkTracer.supports(f.ruleId()));
        if (!hasDollar && !hasSink) {
            return new TraceOutcome(detected, null);
        }
        Map<String, String> sources;
        JavaSourceIndex java;
        try {
            sources = MybatisDollarTracer.readSources(projectDir);
            java = JavaSourceIndex.fromSources(sources);
        } catch (Exception e) {
            log.warn("[{}] 연계 추적용 소스 읽기 실패 — Semgrep 등급 그대로 저장", app.getSystemName(), e);
            return new TraceOutcome(detected, "연계 추적에 실패해 탐지는 Semgrep 등급 그대로 두었습니다. 서버 로그를 확인하세요.");
        }
        List<String> notes = new ArrayList<>();
        if (!java.failedFiles().isEmpty()) {
            log.warn("[{}] 연계 추적이 구문 분석하지 못한 Java 파일: {}", app.getSystemName(), java.failedFiles());
            notes.add("Java 파일 " + java.failedFiles().size() + "개를 구문 분석하지 못해 그 안의 값 세팅·호출은 추적하지 못했습니다.");
        }
        List<DetectedFinding> findings = detected;
        if (hasDollar) {
            try {
                MybatisDollarTracer.Result result = MybatisDollarTracer.trace(sources, java, traceRules);
                DollarTraceMerger.Merged merged = DollarTraceMerger.merge(findings, result.verdicts());
                findings = merged.findings();
                log.info("[{}] MyBatis ${…} 연계 추적: {}건 판정, 맞추지 못함 {}건, 공통 실행 경로 {}개",
                        app.getSystemName(), merged.traced(), merged.unmatched(), result.genericRoutes().size());
                if (merged.unmatched() > 0) {
                    notes.add("${} 탐지 " + merged.unmatched() + "건은 연계 추적 결과와 맞추지 못해 Semgrep 등급 그대로 두었습니다.");
                }
                String ruleNote = checkTraceRules(app, sources, java, traceRules, result);
                if (ruleNote != null) notes.add(ruleNote);
            } catch (Exception e) {
                log.warn("[{}] MyBatis ${…} 연계 추적 실패 — Semgrep 등급 그대로 저장", app.getSystemName(), e);
                notes.add("MyBatis ${} 연계 추적에 실패해 ${} 탐지는 Semgrep 등급 그대로 두었습니다. 서버 로그를 확인하세요.");
            }
        }
        if (hasSink) {
            try {
                List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(java, traceRules).trace(findings);
                findings = SinkTracer.apply(findings, verdicts);
                log.info("[{}] 위험 호출 지점 연계 추적: {}건 판정 {}", app.getSystemName(), verdicts.size(),
                        verdicts.stream().collect(Collectors.groupingBy(v -> v.safety().label(), Collectors.counting())));
            } catch (Exception e) {
                log.warn("[{}] 위험 호출 지점 연계 추적 실패 — Semgrep 등급 그대로 저장", app.getSystemName(), e);
                notes.add("위험 호출 지점(SSRF·명령 실행·파일 경로 등) 연계 추적에 실패해 그 탐지는 Semgrep 등급 그대로 두었습니다. 서버 로그를 확인하세요.");
            }
        }
        return new TraceOutcome(findings, notes.isEmpty() ? null : String.join("\n", notes));
    }

    /**
     * 이 저장소의 프레임워크 장치(세션 값을 요청 맵에 덮어쓰는 AOP, 로그인 정보 타입)가 trace-rules.yml과 맞는지 확인한다(TraceRuleDrafter).
     * 설정이 빠졌거나 틀리면 연계 추적 판정이 조용히 틀린다 — 빠지면 그 ${}가 전부 클라이언트 값(오탐), 세션 값이 아닌 키가 들어가면 위험을 놓친다.
     * 다를 때만 점검 완료 알림에 올리고 초안 YAML은 로그에 남긴다. 설정 파일은 사람이 고친다.
     * 부가 확인이라 실패해도 연계 추적 결과는 그대로 쓴다(로그만).
     */
    private String checkTraceRules(App app, Map<String, String> sources, JavaSourceIndex java, TraceRules current,
                                   MybatisDollarTracer.Result currentResult) {
        try {
            TraceRuleDrafter.Draft draft = TraceRuleDrafter.draft(sources, java);
            draft.notes().forEach(n -> log.info("[{}] 추적 규칙 확인: {}", app.getSystemName(), n));
            List<TraceRuleDraftPreview.Item> items = TraceRuleDraftPreview.compare(current, draft);
            if (items.stream().allMatch(i -> i.status() == TraceRuleDraftPreview.Status.SAME)) {
                return null;
            }
            // 반영했을 때 바뀌는 판정 수 — 설정과 다를 때만 한 번 더 돌린다(평소 점검 시간은 늘지 않는다).
            TraceRules merged = TraceRuleDraftPreview.merge(current, draft, app.getSystemName());
            int changes = TraceRuleDraftPreview.changes(currentResult, MybatisDollarTracer.trace(sources, java, merged)).size();
            log.warn("[{}] 추적 규칙(trace-rules.yml)과 다른 프레임워크 장치가 있습니다. 확인 후 반영할 초안:\n{}",
                    app.getSystemName(), TraceRuleDrafter.toYaml(draft, app.getSystemName()));
            return TraceRuleDraftPreview.note(items, changes);
        } catch (Exception e) {
            log.warn("[{}] 추적 규칙 확인 실패(연계 추적 결과는 그대로 사용)", app.getSystemName(), e);
            return null;
        }
    }

    // 이력 기록은 부가 기능이라 실패해도 점검을 실패시키지 않는다(ScanHistoryService와 같은 이유) — 로그만 남긴다.

    private SecureCodeScan startHistory(App app, String requestedBy) {
        try {
            return scanRepository.save(SecureCodeScan.start(app, requestedBy));
        } catch (Exception e) {
            log.warn("[{}] 코드 점검 이력 시작 기록 실패(점검은 계속 진행): {}", app.getSystemName(), e.toString());
            return null;
        }
    }

    private void succeedHistory(SecureCodeScan history, SemgrepReport report, int findingCount,
                                SecureCodeApplyResult applied, String rulesetVersion) {
        if (history == null) return;
        try {
            history.succeed(report.scannedFileCount(), findingCount, applied.newCount(), applied.resolvedCount(),
                    report.failedFiles().size(), report.engineVersion(), rulesetVersion);
            scanRepository.save(history);
        } catch (Exception e) {
            log.warn("[{}] 코드 점검 이력 완료 기록 실패: {}", history.getSystemName(), e.toString());
        }
    }

    private void failHistory(SecureCodeScan history, Exception cause) {
        if (history == null) return;
        try {
            history.fail(toErrorMessage(cause));
            scanRepository.save(history);
        } catch (Exception e) {
            log.warn("[{}] 코드 점검 이력 실패 기록 실패: {}", history.getSystemName(), e.toString());
        }
    }

    /**
     * 화면에 보일 오류 문구. 우리가 문구를 정한 예외(요청 오류, SecureCodeScanException)만 메시지를 그대로 쓰고,
     * 나머지는 종류만 남긴다 — JGit·파일 예외 메시지에는 서버 임시 디렉터리 경로가 섞인다. 원인은 서버 로그에서 본다.
     */
    static String toErrorMessage(Exception cause) {
        if ((cause instanceof IllegalArgumentException || cause instanceof SecureCodeScanException)
                && cause.getMessage() != null) {
            return cause.getMessage();
        }
        return "코드 점검 도중 오류가 발생했습니다(" + cause.getClass().getSimpleName() + "). 서버 로그를 확인해주세요.";
    }
}
