package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.dto.ai.AiBatchStatus;
import com.sjinc.cvemonitor.service.comcd.ComCdService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 스캔이 새 CVE를 DB에 저장한 직후, 파이썬 AI 판단 배치(ai/vuln_assessor.py)를 백그라운드로 띄운다.
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

    private volatile Process currentProcess;
    private volatile LocalDateTime startedAt;
    private volatile LocalDateTime lastFinishedAt;
    private volatile Integer lastExitCode;

    /**
     * synchronized로 "이미 떠 있으면 건너뛴다" 판단과 새 프로세스 시작 사이에 경합이 생기지
     * 않게 한다 — 이게 없으면 스캔을 연속 호출할 때마다 파이썬 프로세스가 계속 쌓이고, 그
     * 각각이 Claude API를 호출해서(과금) 사실상 DoS가 된다.
     */
    public synchronized void triggerAsync() {
        if (currentProcess != null && currentProcess.isAlive()) {
            log.info("AI 판단 배치가 이미 실행 중이라 이번 트리거는 건너뜁니다.");
            return;
        }

        try {
            // -u(unbuffered): 표준출력이 터미널이 아니라 파일로 리다이렉트되면 파이썬이 기본적으로
            // 블록 버퍼링을 해서, 프로세스가 끝나거나 버퍼가 다 찰 때까지 ai-assessor.log에 아무것도
            // 안 쌓인 것처럼 보인다. 실시간으로 로그를 확인할 수 있도록 무버퍼 모드로 띄운다.
            ProcessBuilder processBuilder = new ProcessBuilder(pythonCommand, "-u", assessorScriptPath);
            // 배치 로그 줄마다 붙는 실행 ID. 아래 "배치 실행 시작" 서버 로그에도 같은 값을 찍어 두 로그를 서로 찾아가게 한다.
            String traceId = UUID.randomUUID().toString().substring(0, 8);
            processBuilder.environment().put("ANTHROPIC_API_KEY", claudeApiKey);
            processBuilder.environment().put("CVE_MONITOR_AI_TOKEN", internalToken);
            processBuilder.environment().put("CVE_MONITOR_BASE_URL", "http://localhost:" + serverPort);
            processBuilder.environment().put("CVE_MONITOR_TRACE_ID", traceId);
            if (!githubToken.isBlank()) {
                processBuilder.environment().put("GITHUB_TOKEN", githubToken);
            }
            // 출력이 파일로 리다이렉트되면 파이썬은 윈도우 기본 인코딩(cp949)으로 쓴다. IDE는 ai-assessor.log를 UTF-8로
            // 열어서(.idea/encodings.xml) 한글이 전부 깨져 보였다 — UTF-8로 쓰게 맞춘다.
            processBuilder.environment().put("PYTHONIOENCODING", "utf-8");
            processBuilder.redirectErrorStream(true);
            processBuilder.redirectOutput(ProcessBuilder.Redirect.appendTo(new File("ai-assessor.log")));

            Process process = processBuilder.start();
            currentProcess = process;
            startedAt = LocalDateTime.now();
            lastExitCode = null;

            process.onExit().thenAccept(finished -> {
                lastExitCode = finished.exitValue();
                lastFinishedAt = LocalDateTime.now();
                log.info("AI 판단 배치 종료(traceId={}): exitCode={}", traceId, lastExitCode);
            });

            log.info("AI 판단 배치 실행 시작(traceId={}): {} {}", traceId, pythonCommand, assessorScriptPath);
        } catch (IOException e) {
            // 파이썬/스크립트를 못 띄워도 스캔 결과 저장 자체는 이미 끝났으므로 스캔을 실패시키지 않는다.
            log.warn("AI 판단 배치 실행 실패 (스캔 결과 저장에는 영향 없음): {}", e.getMessage());
        }
    }

    /** 스캔 후 자동 실행이 켜져 있는가(ScanOrchestrationService가 스캔마다 확인). */
    public boolean isAutoTriggerEnabled() {
        return comCdService.isEnabled(CONFIG_GROUP, AUTO_TRIGGER_CODE, autoTriggerDefault);
    }

    public AiBatchStatus getStatus() {
        boolean running = currentProcess != null && currentProcess.isAlive();
        return new AiBatchStatus(running, startedAt, lastFinishedAt, lastExitCode);
    }
}
