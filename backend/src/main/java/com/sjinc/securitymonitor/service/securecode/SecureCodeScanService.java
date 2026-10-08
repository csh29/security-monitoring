package com.sjinc.securitymonitor.service.securecode;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeScan;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeApplyResult;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeScanResult;
import com.sjinc.securitymonitor.dto.securecode.SemgrepReport;
import com.sjinc.securitymonitor.dto.securecode.TraceStepCode;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.SecureCodeScanRepository;
import com.sjinc.securitymonitor.service.ai.AiAssessmentTriggerService;
import com.sjinc.securitymonitor.service.ai.SecureCodeAiReviewService;
import com.sjinc.securitymonitor.service.git.GitCloneService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import com.sjinc.securitymonitor.exception.SecureCodeScanException;
import com.sjinc.securitymonitor.service.securecode.semgrep.RuleSetLoader;
import com.sjinc.securitymonitor.service.securecode.semgrep.SemgrepReportParser;
import com.sjinc.securitymonitor.service.securecode.semgrep.SemgrepRunner;
import com.sjinc.securitymonitor.service.securecode.trace.DollarTraceMerger;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex;
import com.sjinc.securitymonitor.service.securecode.trace.MybatisDollarTracer;
import com.sjinc.securitymonitor.service.securecode.trace.SinkTracer;
import com.sjinc.securitymonitor.service.securecode.trace.UserScopeFindings;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDraftPreview;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleService;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;

/**
 * 시큐어코딩 점검 1회를 처음부터 끝까지 잇는다: 등록 확인 → clone → Semgrep → 코드 조각·지문 → 기존 탐지와 비교·저장 → 이력.
 *
 * <p>라이브러리 스캔(ScanOrchestrationService)과 서로 부르지 않는다. 공유하는 것은 앱 등록과 clone뿐이다 — 한쪽이 실패하거나
 * 바뀌어도 다른 쪽에 영향이 없게 하기 위함이다. 판정은 결정론(Semgrep + 연계 추적)으로 끝내고, 그래도 못 정한 높은 등급만
 * 점검 뒤 AI 배치가 판별한다(SecureCodeAiReviewService — 여기서는 보낼 코드 문맥을 만들고 배치를 띄우기만 한다).
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
    private final SecureCodeAiReviewService aiReviewService;
    private final AiAssessmentTriggerService aiAssessmentTriggerService;
    private final TraceRuleService traceRuleService;

    /**
     * 한 번에 하나만 돈다. Semgrep은 메모리를 많이 쓰고, 여러 개가 동시에 돌면 사용자 홈의 Semgrep 설정 파일
     * (~/.semgrep/settings.yml)을 같이 쓰다 PermissionError로 실패한다(규칙 테스트 중 실제로 났다).
     */
    private final ReentrantLock scanLock = new ReentrantLock();


    /** 규칙 폴더. 서버를 backend/에서 띄우는 기준(ai.assessor.script와 같은 방식). */
    @Value("${securecode.rules-dir:../securecode/rules}")
    private String rulesDir;

    /** 업로드 zip을 푼 크기의 합 상한(압축 폭탄 방지). 업로드 파일 자체의 크기 상한은 securecode.upload.max-bytes(SecureCodeUploadConfig). */
    @Value("${securecode.upload.max-extracted-bytes:2147483648}")
    private long uploadMaxExtractedBytes;

    @Value("${securecode.upload.max-entries:200000}")
    private int uploadMaxEntries;

    /** 점검 한 번에 쓸 규칙 — 소스를 받기 전에 읽는다(규칙 폴더가 잘못됐으면 clone·압축 해제를 할 필요도 없다). */
    private record Rules(Path dir, RuleSetLoader.RuleSet ruleSet, TraceRules traceRules) {
    }

    /** 잠금·이력 시작·실패 기록 사이에서 실제 일을 하는 부분. */
    @FunctionalInterface
    private interface ScanWork {
        SecureCodeScanResult run() throws Exception;
    }

    /**
     * Git 앱 점검. appId로만 받는다 — 앱 관리에 등록된 저장소만 점검한다(임의 URL clone은 토큰 유출·SSRF 위험, 라이브러리 스캔과 같은 이유).
     *
     * @param requestedBy 점검을 실행한 로그인 아이디(이력에 남긴다)
     */
    public SecureCodeScanResult scan(Long appId, String requestedBy) throws Exception {
        return locked(() -> {
            App app = findApp(appId);
            if (app.isUploadSource()) {
                throw new IllegalArgumentException("소스 업로드 앱입니다 — 소스 zip을 올려 점검하세요.");
            }
            SecureCodeScan history = saveHistory(SecureCodeScan.start(app, requestedBy), app);
            return withHistory(history, () -> {
                Rules rules = loadRules();
                File projectDir = gitCloneService.cloneRepository(app.getRepoUrl(), app.getBranch());
                try {
                    return analyze(app, history, projectDir.toPath(), rules);
                } finally {
                    gitCloneService.cleanup(projectDir);
                }
            });
        });
    }

    /**
     * 소스 업로드 앱 점검 — Git으로 접근할 수 없는 앱의 소스 zip을 받아 풀고 Git 점검과 같은 과정을 돈다(SourceArchiveExtractor).
     * 업로드 앱만 받는다 — Git 앱을 zip으로 점검하면 경로 기준이 달라져 탐지가 "해결+신규"로 뒤섞인다. 점검할 소스 파일이 하나도 없는 zip은 거부한다
     * — 받아들이면 기존 탐지가 전부 "해결"이 된다(빈 zip 하나로 결과를 지울 수 있게 된다). 올린 zip과 푼 폴더는 점검이 끝나면 지운다.
     *
     * @param fileName 올린 파일 이름(이력에 남긴다)
     * @param content  zip 내용
     */
    public SecureCodeScanResult scanUpload(Long appId, String requestedBy, String fileName, InputStream content) throws Exception {
        return locked(() -> {
            App app = findApp(appId);
            if (!app.isUploadSource()) {
                throw new IllegalArgumentException("Git 앱입니다 — 저장소에서 받아 점검합니다(앱 관리에서 소스 출처가 '소스 업로드'인 앱만 zip으로 점검).");
            }
            if (fileName == null || !fileName.toLowerCase(Locale.ROOT).endsWith(".zip")) {
                throw new IllegalArgumentException("zip 파일만 올릴 수 있습니다.");
            }
            SecureCodeScan history = saveHistory(SecureCodeScan.startUpload(app, requestedBy, fileName), app);
            return withHistory(history, () -> {
                Rules rules = loadRules();
                Path zip = Files.createTempFile("securecode-upload-", ".zip");
                Path projectDir = Files.createTempDirectory("securecode-src-");
                try {
                    String sha256 = copyWithHash(content, zip);
                    if (history != null) history.recordUploadHash(sha256);
                    SourceArchiveExtractor.Result extracted = SourceArchiveExtractor.extract(zip, projectDir,
                            new SourceArchiveExtractor.Limits(uploadMaxExtractedBytes, uploadMaxEntries));
                    if (extracted.sourceFileCount() == 0) {
                        throw new IllegalArgumentException("zip에 점검할 소스 파일(.java·.jsp·.xml 등)이 없습니다. 프로젝트 소스 폴더를 압축했는지 확인하세요.");
                    }
                    log.info("[{}] 업로드 소스 압축 해제: {} 파일 {}개(소스 {}개), 벗긴 최상위 폴더 {}", app.getSystemName(), fileName,
                            extracted.fileCount(), extracted.sourceFileCount(), extracted.strippedRoot());
                    return analyze(app, history, projectDir, rules);
                } finally {
                    Files.deleteIfExists(zip);
                    gitCloneService.cleanup(projectDir.toFile());
                }
            });
        });
    }

    @Transactional(readOnly = true)
    public List<SecureCodeScan> getHistories(Long appId) {
        return scanRepository.findLatest(appId, PageRequest.of(0, MAX_HISTORY_ROWS));
    }

    private SecureCodeScanResult locked(ScanWork work) throws Exception {
        if (!scanLock.tryLock()) {
            throw SecureCodeScanException.busy();
        }
        try {
            return work.run();
        } finally {
            scanLock.unlock();
        }
    }

    private SecureCodeScanResult withHistory(SecureCodeScan history, ScanWork work) throws Exception {
        try {
            return work.run();
        } catch (Exception e) {
            failHistory(history, e);
            throw e;
        }
    }

    private App findApp(Long appId) {
        return appRepository.findById(appId)
                .orElseThrow(() -> new IllegalArgumentException("앱 관리에 등록되지 않은 앱입니다: appId=" + appId));
    }

    private Rules loadRules() throws IOException {
        Path dir = Path.of(rulesDir);
        return new Rules(dir, new RuleSetLoader().load(dir, List.of(traceRuleService.judgmentContent())), traceRuleService.load());
    }

    /** zip을 임시 파일로 받으면서 내용 해시를 구한다(이력에 남겨 어떤 소스로 점검했는지 맞춰 볼 수 있게). */
    private static String copyWithHash(InputStream content, Path target) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream in = new DigestInputStream(content, digest)) {
                Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 받은 소스 폴더(clone 또는 업로드 압축 해제)를 점검하고 결과를 저장한다. 소스를 얻는 방법만 다르고 나머지는 같다. */
    private SecureCodeScanResult analyze(App app, SecureCodeScan history, Path projectDir, Rules rulesInUse) throws Exception {
        Path rules = rulesInUse.dir();
        RuleSetLoader.RuleSet ruleSet = rulesInUse.ruleSet();
        TraceRules traceRules = rulesInUse.traceRules();
        SemgrepReport report = new SemgrepReportParser(objectMapper)
                .parse(semgrepRunner.run(projectDir, rules));
        SecureCodeSnippetBuilder snippetBuilder = new SecureCodeSnippetBuilder(projectDir);
        List<DetectedFinding> detected = snippetBuilder.build(report.matches());
        TraceOutcome trace = traceFindings(app, projectDir, detected, traceRules, snippetBuilder);
        // 같은 줄·같은 CWE를 다른 방식으로 보는 규칙 쌍(taint + 실행 호출 등)은 한 건으로 — 판정이 엇갈리지 않게, AI 대상도 남은 건 기준으로.
        DuplicateCweMerger.Merged merged = DuplicateCweMerger.merge(trace.findings());
        if (!merged.mergedAway().isEmpty()) {
            log.info("[{}] 같은 줄·같은 CWE 탐지 {}건을 합침", app.getSystemName(), merged.mergedAway().size());
        }
        detected = attachAiContext(app, snippetBuilder, merged.findings());
        detected = attachTraceCode(app, projectDir, snippetBuilder, detected);

        // 사용자 범위 판정은 Semgrep 규칙이 아니라 판정이 만드는 탐지라 규칙셋에 없다. 이번에 판정을 했을 때만 활성 규칙에 넣는다 —
        // 판정이 실패했거나 설정이 없어 안 했는데 넣으면 기존 탐지가 전부 "해결"로 바뀐다(못 본 것이지 고친 게 아니다).
        Set<String> activeRuleIds = new HashSet<>(ruleSet.ruleIds());
        if (trace.rulesChanged()) ruleSet = reloadRuleSet(app, rules, ruleSet);
        if (trace.userScopeJudged()) activeRuleIds.add(UserScopeFindings.RULE_ID);

        SecureCodeApplyResult applied = findingService.applyScan(
                app.getId(), detected, report.failedFiles(), activeRuleIds, merged.mergedAway());

        log.info("[{}] 코드 점검 완료: 파일 {}개, 탐지 {}건(신규 {}, 해결 {}), 분석 실패 파일 {}개",
                app.getSystemName(), report.scannedFileCount(), detected.size(),
                applied.newCount(), applied.resolvedCount(), report.failedFiles().size());
        if (!report.failedFiles().isEmpty()) {
            log.warn("[{}] Semgrep이 끝까지 보지 못한 파일: {}", app.getSystemName(), report.failedFiles());
        }

        succeedHistory(history, report, detected.size(), applied, ruleSet.version());
        triggerAiReviewIfNeeded(app);
        return new SecureCodeScanResult(app.getSystemName(), report.scannedFileCount(), detected.size(),
                applied.newCount(), applied.resolvedCount(), report.failedFiles().size(), trace.note());
    }

    /**
     * 연계 추적 결과. note는 화면 알림에 덧붙일 문구(문제가 없으면 null).
     * userScopeJudged는 사용자 범위 판정을 끝까지 했는가 — 했을 때만 그 판정의 기존 탐지를 해결 처리할 수 있다.
     * rulesChanged는 이번 점검이 추적 규칙 파일을 고쳤는가(TraceRuleService.review) — 고쳤으면 규칙셋 버전을 다시 계산한다.
     */
    private record TraceOutcome(List<DetectedFinding> findings, String note, boolean userScopeJudged, boolean rulesChanged) {
    }

    /** 점검 중 추적 규칙을 고쳤으면 이력의 규칙셋 버전도 고친 규칙 기준으로 — 같은 코드라도 판정이 달라진 이유를 이력에서 찾을 수 있게. */
    private RuleSetLoader.RuleSet reloadRuleSet(App app, Path rulesDir, RuleSetLoader.RuleSet current) {
        try {
            return new RuleSetLoader().load(rulesDir, List.of(traceRuleService.judgmentContent()));
        } catch (Exception e) {
            log.warn("[{}] 규칙셋 버전을 다시 계산하지 못했습니다(점검 시작 때 버전으로 기록)", app.getSystemName(), e);
            return current;
        }
    }

    /**
     * 출처를 따라갈 수 있는 탐지에 연계 추적 판정·근거를 붙이고 등급을 다시 매긴다.
     * <ul>
     *   <li>MyBatis ${}(MybatisDollarTracer) — 값이 클라이언트에서 오는지, 서버가 세팅하는지, 공통 실행 경로로 우회되는지</li>
     *   <li>위험 호출 지점(SinkTracer) — SSRF 변수 주소·명령 실행·다운로드 경로·업로드 저장·문자열 연결 SQL에 들어가는 값의 출처</li>
     *   <li>사용자 범위(UserScopeFindings) — trace-rules.yml userScopeKeys가 쓰인 매퍼 SQL마다 그 값을 클라이언트가 정할 수 있는지.
     *       Semgrep 탐지에 판정을 붙이는 게 아니라 판정에서 탐지를 만든다</li>
     * </ul>
     * Java 구문 분석은 한 번만 하고 모두 같은 색인을 쓴다. 추적은 부가 판정이라 실패해도 점검을 실패시키지 않는다 — 대신 Semgrep 등급을
     * 그대로 두고(모르면 위험한 쪽), 그 사실을 화면 알림으로 올린다. "추적이 돌아서 안전해 보이는 것"과 "추적을 못 한 것"을 구분할 수 있어야 한다.
     *
     * <p>추적 전에 이 저장소의 프레임워크 장치·설정 파일로 추적 규칙을 확인한다(TraceRuleService.review) — 판정을 엄격하게 하는 변경은
     * 바로 반영해 이번 추적부터 쓰고, 느슨하게 하는 변경은 확인 대기로 남긴다. 새 시스템은 사용자 범위 키가 설정에 없어도 초안이 후보를
     * 찾아야 해서, 추적할 탐지가 없어도 소스는 읽는다.
     */
    private TraceOutcome traceFindings(App app, Path projectDir, List<DetectedFinding> detected, TraceRules traceRules,
                                      SecureCodeSnippetBuilder snippetBuilder) {
        boolean hasDollar = detected.stream().anyMatch(f -> DollarTraceMerger.RULE_IDS.contains(f.ruleId()));
        boolean hasSink = detected.stream().anyMatch(f -> SinkTracer.supports(f.ruleId()));
        Map<String, String> sources;
        JavaSourceIndex java;
        try {
            sources = MybatisDollarTracer.readSources(projectDir);
            java = JavaSourceIndex.fromSources(sources);
        } catch (Exception e) {
            log.warn("[{}] 연계 추적용 소스 읽기 실패 — Semgrep 등급 그대로 저장", app.getSystemName(), e);
            return new TraceOutcome(detected, "연계 추적에 실패해 탐지는 Semgrep 등급 그대로 두었고 사용자 범위(인가) 판정은 하지 못했습니다. "
                    + "서버 로그를 확인하세요.", false, false);
        }
        List<String> notes = new ArrayList<>();
        TraceRuleService.Review review = traceRuleService.review(app, sources, java, traceRules);
        traceRules = review.rules();
        if (review.note() != null) notes.add(review.note());
        boolean hasScope = !traceRules.userScopeKeys().isEmpty();
        if (!hasScope) {
            notes.add("trace-rules.yml에 userScopeKeys(사용자 범위 키)가 없어 사용자 범위(인가) 판정을 하지 않았습니다. "
                    + "회사·사용자로 데이터를 가르는 SQL 파라미터 키를 추가하세요.");
        }
        if (!java.failedFiles().isEmpty()) {
            log.warn("[{}] 연계 추적이 구문 분석하지 못한 Java 파일: {}", app.getSystemName(), java.failedFiles());
            notes.add("Java 파일 " + java.failedFiles().size() + "개를 구문 분석하지 못해 그 안의 값 세팅·호출은 추적하지 못했습니다.");
        }
        List<DetectedFinding> findings = detected;
        boolean userScopeJudged = false;
        MybatisDollarTracer.Result result = null;
        if (hasDollar || hasScope) {
            // ${} 판정과 사용자 범위 판정은 같은 엔진이 한 번에 낸다(구문 실행 위치 찾기를 한 번만 하게).
            try {
                result = MybatisDollarTracer.trace(sources, java, traceRules);
            } catch (Exception e) {
                log.warn("[{}] MyBatis 연계 추적 실패 — ${…} 탐지는 Semgrep 등급 그대로, 사용자 범위 판정 없음", app.getSystemName(), e);
                notes.add("MyBatis 연계 추적에 실패해 ${} 탐지는 Semgrep 등급 그대로 두었고 사용자 범위(인가) 판정은 하지 못했습니다. "
                        + "서버 로그를 확인하세요.");
            }
            if (result != null && hasDollar) {
                DollarTraceMerger.Merged merged = DollarTraceMerger.merge(findings, result.verdicts());
                findings = merged.findings();
                log.info("[{}] MyBatis ${…} 연계 추적: {}건 판정, 맞추지 못함 {}건, 공통 실행 경로 {}개",
                        app.getSystemName(), merged.traced(), merged.unmatched(), result.genericRoutes().size());
                if (merged.unmatched() > 0) {
                    notes.add("${} 탐지 " + merged.unmatched() + "건은 연계 추적 결과와 맞추지 못해 Semgrep 등급 그대로 두었습니다.");
                }
            }
            if (result != null && hasScope) {
                try {
                    List<DetectedFinding> scope = UserScopeFindings.build(result.scopeVerdicts(), snippetBuilder);
                    findings = new ArrayList<>(findings);
                    findings.addAll(scope);
                    userScopeJudged = true;
                    log.info("[{}] 사용자 범위 판정: 키 사용 {}곳, 탐지 {}건 {}", app.getSystemName(), result.scopeVerdicts().size(),
                            scope.size(), result.scopeVerdicts().stream()
                                    .collect(Collectors.groupingBy(v -> v.safety().label(), Collectors.counting())));
                    if (!result.scopeKeysUsed()) {
                        // 키가 설정돼 있어도 이 시스템이 다른 이름을 쓰면 아무것도 안 걸린다 — "문제 없음"과 구분되게 알린다.
                        notes.add("이 저장소의 매퍼 SQL에서 사용자 범위 키(" + String.join(", ", traceRules.userScopeKeys())
                                + ")를 찾지 못했습니다. 이 시스템이 회사·사용자 범위에 쓰는 키를 trace-rules.yml userScopeKeys에 추가하세요.");
                    }
                } catch (Exception e) {
                    log.warn("[{}] 사용자 범위 탐지 만들기 실패", app.getSystemName(), e);
                    notes.add("사용자 범위(인가) 판정 결과로 탐지를 만들지 못했습니다. 서버 로그를 확인하세요.");
                }
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
        String pendingNote = pendingRuleNote(app, sources, java, review, result);
        if (pendingNote != null) notes.add(pendingNote);
        return new TraceOutcome(findings, notes.isEmpty() ? null : String.join("\n", notes), userScopeJudged, review.rulesChanged());
    }

    /**
     * 확인 대기 추적 규칙 안내 — 반영하면 바뀌는 판정 수를 붙인다(지금 규칙과 대기 변경을 반영한 규칙으로 추적을 한 번 더 돌린 차이).
     * 대기가 있을 때만 한 번 더 돌린다(평소 점검 시간은 늘지 않는다). 부가 안내라 실패하면 건수 없이 안내만 한다.
     */
    private String pendingRuleNote(App app, Map<String, String> sources, JavaSourceIndex java, TraceRuleService.Review review,
                                   MybatisDollarTracer.Result current) {
        if (review.pending().isEmpty()) return null;
        int changes;
        try {
            MybatisDollarTracer.Result before = current != null ? current : MybatisDollarTracer.trace(sources, java, review.rules());
            changes = TraceRuleDraftPreview.changes(before, MybatisDollarTracer.trace(sources, java, review.withPending())).size();
        } catch (Exception e) {
            log.warn("[{}] 추적 규칙 대기 변경의 판정 영향을 계산하지 못했습니다", app.getSystemName(), e);
            changes = 0;
        }
        return traceRuleService.pendingNote(review, changes);
    }

    /**
     * 연계 추적 근거 걸음마다 그 줄 주변 코드를 붙인다(상세보기에서 근거를 눌러 본다). 근거는 다른 파일·메서드를 가리키는데 clone은 점검이 끝나면
     * 지우므로 지금 만들어 둔다. 부가 기능이라 실패해도 점검을 실패시키지 않는다 — 근거 글만 보인다.
     */
    private List<DetectedFinding> attachTraceCode(App app, Path projectDir, SecureCodeSnippetBuilder snippetBuilder,
                                                  List<DetectedFinding> findings) {
        if (findings.stream().allMatch(f -> f.traceEvidence() == null)) return findings;
        Map<String, List<String>> pathsByFileName;
        try (Stream<Path> files = Files.walk(projectDir)) {
            pathsByFileName = files.filter(Files::isRegularFile)
                    .map(f -> projectDir.relativize(f).toString().replace('\\', '/'))
                    .filter(f -> !f.startsWith(".git/") && (f.endsWith(".java") || f.endsWith(".xml")))
                    .collect(Collectors.groupingBy(f -> f.substring(f.lastIndexOf('/') + 1)));
        } catch (IOException e) {
            log.warn("[{}] 연계 추적 코드를 붙이지 못했습니다(소스 목록 실패): {}", app.getSystemName(), e.toString());
            return findings;
        }
        List<DetectedFinding> result = new ArrayList<>(findings.size());
        int attached = 0;
        for (DetectedFinding f : findings) {
            try {
                List<TraceStepCode> code = snippetBuilder.traceCode(f, pathsByFileName);
                if (code == null) {
                    result.add(f);
                    continue;
                }
                result.add(f.withTraceCode(objectMapper.writeValueAsString(code)));
                attached++;
            } catch (Exception e) {
                log.warn("[{}] 연계 추적 코드를 붙이지 못했습니다({}:{}): {}", app.getSystemName(), f.filePath(), f.startLine(), e.toString());
                result.add(f);
            }
        }
        log.info("[{}] 연계 추적 근거 코드 {}건에 붙임", app.getSystemName(), attached);
        return result;
    }

    /**
     * AI 판별 대상(결정론으로 못 정한 높은 등급)에 보낼 코드 문맥을 붙인다. 등급은 연계 추적이 다시 매긴 뒤라야 정해져서 추적 뒤에 한다.
     * clone이 지워지기 전에만 만들 수 있다. 부가 기능이라 실패해도 점검을 실패시키지 않는다 — 문맥이 없으면 화면용 조각을 보낸다.
     */
    private List<DetectedFinding> attachAiContext(App app, SecureCodeSnippetBuilder snippetBuilder, List<DetectedFinding> findings) {
        List<DetectedFinding> result = new ArrayList<>(findings.size());
        int attached = 0;
        for (DetectedFinding f : findings) {
            if (!aiReviewService.isTarget(f.ruleId(), f.severity(), f.traceSafety())) {
                result.add(f);
                continue;
            }
            try {
                result.add(snippetBuilder.withAiContext(f));
                attached++;
            } catch (Exception e) {
                log.warn("[{}] AI 판별용 코드 문맥을 만들지 못했습니다({}:{}) — 화면용 조각을 보냅니다: {}",
                        app.getSystemName(), f.filePath(), f.startLine(), e.toString());
                result.add(f);
            }
        }
        if (attached > 0) {
            log.info("[{}] AI 판별 대상 {}건에 코드 문맥을 붙임", app.getSystemName(), attached);
        }
        return result;
    }

    /**
     * 판별 대기가 있으면 시큐어코딩 AI 배치만 띄운다(로그는 ai-securecode.log — CVE 단계는 돌리지 않는다). 라이브러리 스캔과 같은 자동 실행
     * 스위치(공통코드 AI_CONFIG/AUTO_TRIGGER)를 따른다 — 배치는 Claude API를 호출해 과금된다. 시큐어코딩 배치가 이미 떠 있으면
     * triggerAsync가 건너뛰고, 남은 대기는 다음 배치가 가져간다.
     * 실패해도 점검 결과는 이미 저장됐으니 로그만 남긴다.
     */
    private void triggerAiReviewIfNeeded(App app) {
        try {
            if (!aiAssessmentTriggerService.isAutoTriggerEnabled()) {
                log.info("[{}] 공통코드 {}/{}가 꺼져 있어 코드 점검 후 AI 판별 배치를 띄우지 않습니다.", app.getSystemName(),
                        AiAssessmentTriggerService.CONFIG_GROUP, AiAssessmentTriggerService.AUTO_TRIGGER_CODE);
                return;
            }
            int pending = aiReviewService.getPendingTargets().size();
            if (pending > 0) {
                log.info("[{}] AI 판별 대기 {}건(전체 앱) — AI 배치를 띄웁니다.", app.getSystemName(), pending);
                aiAssessmentTriggerService.triggerAsync(AiAssessmentTriggerService.BatchKind.SECURE_CODE);
            }
        } catch (Exception e) {
            log.warn("[{}] AI 판별 배치 실행 판단/시작 실패(점검 결과는 저장됨): {}", app.getSystemName(), e.toString());
        }
    }

    // 이력 기록은 부가 기능이라 실패해도 점검을 실패시키지 않는다(ScanHistoryService와 같은 이유) — 로그만 남긴다.

    private SecureCodeScan saveHistory(SecureCodeScan started, App app) {
        try {
            return scanRepository.save(started);
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
