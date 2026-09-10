package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.dto.ai.AiBatchStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;

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
public class AiAssessmentTriggerService {

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

    private volatile Process currentProcess;
    private volatile LocalDateTime startedAt;
    private volatile LocalDateTime lastFinishedAt;
    private volatile Integer lastExitCode;

    public void triggerAsync() {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(pythonCommand, assessorScriptPath);
            processBuilder.environment().put("ANTHROPIC_API_KEY", claudeApiKey);
            processBuilder.environment().put("CVE_MONITOR_AI_TOKEN", internalToken);
            processBuilder.environment().put("CVE_MONITOR_BASE_URL", "http://localhost:" + serverPort);
            processBuilder.redirectErrorStream(true);
            processBuilder.redirectOutput(ProcessBuilder.Redirect.appendTo(new File("ai-assessor.log")));

            Process process = processBuilder.start();
            currentProcess = process;
            startedAt = LocalDateTime.now();
            lastExitCode = null;

            process.onExit().thenAccept(finished -> {
                lastExitCode = finished.exitValue();
                lastFinishedAt = LocalDateTime.now();
                log.info("AI 판단 배치 종료: exitCode={}", lastExitCode);
            });

            log.info("AI 판단 배치 실행 시작: {} {}", pythonCommand, assessorScriptPath);
        } catch (IOException e) {
            // 파이썬/스크립트를 못 띄워도 스캔 결과 저장 자체는 이미 끝났으므로 스캔을 실패시키지 않는다.
            log.warn("AI 판단 배치 실행 실패 (스캔 결과 저장에는 영향 없음): {}", e.getMessage());
        }
    }

    public AiBatchStatus getStatus() {
        boolean running = currentProcess != null && currentProcess.isAlive();
        return new AiBatchStatus(running, startedAt, lastFinishedAt, lastExitCode);
    }
}
