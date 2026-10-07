package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.dto.ai.AiBatchStatus;
import com.sjinc.securitymonitor.service.comcd.ComCdService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;

/**
 * 스캔이 끝난 뒤 파이썬 AI 배치(ai/vuln_assessor.py)를 백그라운드로 띄운다 — 라이브러리 스캔 뒤에는 CVE 단계, 코드 점검 뒤에는
 * 시큐어코딩 단계만({@link BatchKind}).
 *
 * <p>배치는 자바를 거치지 않고 /api/ai/** 를 직접 호출해 대기 중인 취약점을 스스로 가져가므로,
 * 여기서는 프로세스만 띄우고 결과를 기다리지 않는다(fire-and-forget). AI 판단이 느리거나 실패해도
 * 스캔 자체(진짜 목적)는 이미 끝난 뒤라 영향이 없다.
 *
 * <p>다만 "지금 돌고 있는지"를 물어볼 수 있도록, 마지막으로 띄운 프로세스 핸들과 시작/종료 시각을
 * 기억해뒀다가 {@link #getStatus()}로 내려준다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AiAssessmentTriggerService {

    /**
     * 스캔 후 자동 실행 스위치 — 공통코드 AI_CONFIG / AUTO_TRIGGER의 사용여부(Y=켜짐). 배치는 Claude API를 호출해
     * 과금되므로 스캔을 반복하는 개발·테스트 때 끌 수 있게 둔다. 공통코드 관리 화면에서 바꾸면 다음 스캔부터 바로 적용된다.
     */
    public static final String CONFIG_GROUP = "AI_CONFIG";
    public static final String AUTO_TRIGGER_CODE = "AUTO_TRIGGER";

    private final ComCdService comCdService;

    /**
     * 자동 실행 스위치의 초기값. DB를 처음 만들 때 공통코드를 이 값으로 심는다(DataInitializer) — 그 뒤로는 공통코드 값이 기준이다.
     * 공통코드가 지워져 없을 때도 이 값을 쓴다. 실행 중 켜고 끄기는 공통코드로 한다.
     */
    @Value("${ai.auto-trigger.enabled:true}")
    private boolean autoTriggerDefault;

    @Value("${ai.assessor.script}")
    private String assessorScriptPath;

    @Value("${ai.python.command:py}")
    private String pythonCommand;

    @Value("${ai.internal.token}")
    private String internalToken;

    @Value("${claude.api.key}")
    private String claudeApiKey;

    @Value("${server.port:8080}")
    private String serverPort;

    /**
     * 영향 분석(stage 4)이 GitHub 릴리스 노트를 받을 때 쓰는 읽기 전용 토큰. 선택값이다 — 없으면 토큰 없이 부르고
     * (IP당 시간당 60회), 한도에 걸린 건은 FETCH_FAILED로 남아 다음 배치에서 다시 시도된다.
     */
    @Value("${github.token:}")
    private String githubToken;

    /**
     * 배치 종류. 라이브러리 스캔 뒤에는 CVE 단계만, 코드 점검 뒤에는 시큐어코딩 단계만 띄운다 — 예전엔 어느 쪽이든 전체를 돌려서
     * 코드 점검 뒤 로그에도 할 일 없는 CVE 단계(CVE 판단 0건, fix-plan …)가 찍혔다. 둘은 동시에 돌 수 있어 로그 파일도 나눈다
     * (같은 파일이면 두 실행의 줄이 섞인다).
     *
     * @param arg     vuln_assessor.py에 넘기는 기능 인자(파이썬 STAGES의 키와 같아야 한다)
     * @param logFile 표준출력·표준에러를 이어 붙일 파일(backend/ 기준, gitignore 대상)
     */
    public enum BatchKind {
        CVE("cve", "ai-assessor.log", "라이브러리 취약점"),
        SECURE_CODE("securecode", "ai-securecode.log", "시큐어코딩");

        final String arg;
        final String logFile;
        final String label;

        BatchKind(String arg, String logFile, String label) {
            this.arg = arg;
            this.logFile = logFile;
            this.label = label;
        }
    }

    /** 종류별로 마지막에 띄운 프로세스와 시각. "이미 떠 있으면 건너뜀"도 종류별이다 — 한쪽이 돌고 있다고 다른 쪽 대기를 다음 실행까지 미루지 않는다. */
    private static final class RunState {
        volatile Process process;
        volatile LocalDateTime startedAt;
        volatile LocalDateTime lastFinishedAt;
        volatile Integer lastExitCode;
    }

    private final Map<BatchKind, RunState> states = new EnumMap<>(Map.of(
            BatchKind.CVE, new RunState(), BatchKind.SECURE_CODE, new RunState()));

    /**
     * synchronized로 "이미 떠 있으면 건너뛴다" 판단과 새 프로세스 시작 사이에 경합이 생기지
     * 않게 한다 — 이게 없으면 스캔을 연속 호출할 때마다 파이썬 프로세스가 계속 쌓이고, 그
     * 각각이 Claude API를 호출해서(과금) 사실상 DoS가 된다. 종류마다 최대 하나다.
     */
    public synchronized void triggerAsync(BatchKind kind) {
        RunState state = states.get(kind);
        if (state.process != null && state.process.isAlive()) {
            log.info("{} AI 배치가 이미 실행 중이라 이번 트리거는 건너뜁니다.", kind.label);
            return;
        }

        try {
            // -u(unbuffered): 표준출력이 터미널이 아니라 파일로 리다이렉트되면 파이썬이 기본적으로
            // 블록 버퍼링을 해서, 프로세스가 끝나거나 버퍼가 다 찰 때까지 로그 파일에 아무것도
            // 안 쌓인 것처럼 보인다. 실시간으로 로그를 확인할 수 있도록 무버퍼 모드로 띄운다.
            ProcessBuilder processBuilder = new ProcessBuilder(pythonCommand, "-u", assessorScriptPath, kind.arg);
            // 배치 로그 줄마다 붙는 실행 ID. 아래 "배치 실행 시작" 서버 로그에도 같은 값을 찍어 두 로그를 서로 찾아가게 한다.
            String traceId = UUID.randomUUID().toString().substring(0, 8);
            processBuilder.environment().put("ANTHROPIC_API_KEY", claudeApiKey);
            processBuilder.environment().put("SECURITY_MONITOR_AI_TOKEN", internalToken);
            processBuilder.environment().put("SECURITY_MONITOR_BASE_URL", "http://localhost:" + serverPort);
            processBuilder.environment().put("SECURITY_MONITOR_TRACE_ID", traceId);
            if (!githubToken.isBlank()) {
                processBuilder.environment().put("GITHUB_TOKEN", githubToken);
            }
            // 출력이 파일로 리다이렉트되면 파이썬은 윈도우 기본 인코딩(cp949)으로 쓴다. IDE는 로그 파일을 UTF-8로
            // 열어서(.idea/encodings.xml) 한글이 전부 깨져 보였다 — UTF-8로 쓰게 맞춘다.
            processBuilder.environment().put("PYTHONIOENCODING", "utf-8");
            processBuilder.redirectErrorStream(true);
            processBuilder.redirectOutput(ProcessBuilder.Redirect.appendTo(new File(kind.logFile)));

            Process process = processBuilder.start();
            state.process = process;
            state.startedAt = LocalDateTime.now();
            state.lastExitCode = null;

            process.onExit().thenAccept(finished -> {
                state.lastExitCode = finished.exitValue();
                state.lastFinishedAt = LocalDateTime.now();
                log.info("{} AI 배치 종료(traceId={}): exitCode={}", kind.label, traceId, state.lastExitCode);
            });

            log.info("{} AI 배치 실행 시작(traceId={}, 로그 {}): {} {} {}", kind.label, traceId, kind.logFile,
                    pythonCommand, assessorScriptPath, kind.arg);
        } catch (IOException e) {
            // 파이썬/스크립트를 못 띄워도 스캔 결과 저장 자체는 이미 끝났으므로 스캔을 실패시키지 않는다.
            log.warn("{} AI 배치 실행 실패 (스캔 결과 저장에는 영향 없음): {}", kind.label, e.getMessage());
        }
    }

    /** 스캔 후 자동 실행이 켜져 있는가(ScanOrchestrationService가 스캔마다 확인). */
    public boolean isAutoTriggerEnabled() {
        return comCdService.isEnabled(CONFIG_GROUP, AUTO_TRIGGER_CODE, autoTriggerDefault);
    }

    /** 종류별 실행 상태(배치 종류 이름 → 상태). */
    public Map<BatchKind, AiBatchStatus> getStatus() {
        Map<BatchKind, AiBatchStatus> result = new EnumMap<>(BatchKind.class);
        states.forEach((kind, state) -> result.put(kind, new AiBatchStatus(
                state.process != null && state.process.isAlive(), state.startedAt, state.lastFinishedAt, state.lastExitCode)));
        return result;
    }
}
