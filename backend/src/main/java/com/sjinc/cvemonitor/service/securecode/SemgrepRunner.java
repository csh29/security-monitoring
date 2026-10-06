package com.sjinc.cvemonitor.service.securecode;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * clone한 저장소에 Semgrep을 실행하고 결과 JSON 문자열을 돌려준다.
 *
 * <p>Semgrep은 대상 코드를 실행하지 않고 읽기만 한다(Maven을 돌리는 라이브러리 스캔보다 위험이 작다). 규칙은 저장소 안의
 * 파일만 쓰고 통계 전송을 끈다 — 코드도 규칙도 외부로 나가지 않는다.
 */
@Slf4j
@Component
public class SemgrepRunner {

    /**
     * clone한 저장소 루트에 덮어쓰는 제외 목록. 저장소에 원래 있던 .semgrepignore를 그대로 따르면 점검 대상 쪽에서
     * 원하는 파일을 점검에서 뺄 수 있고, Semgrep 기본 목록은 버전마다 달라 무엇이 빠지는지 우리가 모른다.
     * 테스트 코드는 운영 코드가 아니라 뺀다.
     */
    static final String IGNORE_FILE_CONTENT = String.join("\n",
            ".git/", "target/", "build/", "out/", "node_modules/", ".idea/", ".gradle/",
            "src/test/", "*.min.js", "*.map", "");

    static final String DEFAULT_COMMAND = "semgrep";

    /**
     * semgrep 실행 파일. 설정하지 않으면 PATH의 semgrep을 쓰고, 없으면 AI 배치와 같은 파이썬(ai.python.command)의
     * Scripts 폴더에서 찾는다 — pip로 설치하면 거기에 들어가는데 윈도우에선 PATH에 없는 경우가 많다(이 PC가 그랬다).
     */
    @Value("${securecode.semgrep.command:" + DEFAULT_COMMAND + "}")
    private String semgrepCommand;

    @Value("${ai.python.command:py}")
    private String pythonCommand;

    /** 파이썬 Scripts 폴더에서 찾은 경로. 한 번 찾으면 기억한다(찾을 때마다 파이썬을 띄우지 않게). */
    private volatile String discoveredCommand;

    /** 규칙 폴더. 그 옆의 requirements.txt(고정 버전)를 기동 점검에서 읽는다. SecureCodeScanService와 같은 키. */
    @Value("${securecode.rules-dir:../securecode/rules}")
    private String rulesDir;

    private static final Pattern PINNED_VERSION = Pattern.compile("(?m)^\\s*semgrep\\s*==\\s*([\\w.]+)");
    private static final Pattern VERSION = Pattern.compile("(\\d+\\.\\d+\\.\\d+)");

    /** 점검 1회 전체 제한시간. 넘기면 프로세스를 강제 종료하고 점검을 실패로 남긴다. */
    @Value("${securecode.timeout-seconds:600}")
    private long timeoutSeconds;

    public String run(Path projectDir, Path rulesDir) throws IOException, InterruptedException {
        // 저장소에 같은 이름의 심볼릭 링크가 있으면 그대로 쓰면 링크가 가리키는 서버 파일을 덮어쓴다 — 지우고 새로 만든다.
        Path ignoreFile = projectDir.resolve(".semgrepignore");
        Files.deleteIfExists(ignoreFile);
        Files.writeString(ignoreFile, IGNORE_FILE_CONTENT, StandardCharsets.UTF_8);

        // 결과·로그 파일은 clone 밖에 둔다(안에 두면 다음 점검 대상이 되진 않지만 이번 점검이 자기 출력 파일을 읽으려 한다).
        Path output = Files.createTempFile("secure-code-", ".json");
        Path logFile = Files.createTempFile("secure-code-", ".log");
        try {
            // 바꿀 수 있는 리스트로 넘긴다 — 실행 파일을 못 찾으면 start()가 첫 인자를 찾은 경로로 바꿔 다시 시도한다.
            ProcessBuilder builder = new ProcessBuilder(new ArrayList<>(List.of(
                    command(), "scan",
                    "--config", rulesDir.toAbsolutePath().toString(),
                    "--json", "--output", output.toString(),
                    "--metrics=off", "--disable-version-check",
                    // 파일 하나에 규칙 하나가 30초를 넘기면 그 파일은 errors(분석 실패 파일)로 넘긴다.
                    "--timeout", "30",
                    // clone은 추적 파일만 있어서 .gitignore로 거를 게 없다. 대신 git 실행 파일이 없는 서버에서도 돌게 한다.
                    "--no-git-ignore",
                    ".")));
            builder.directory(projectDir.toFile());
            builder.environment().put("SEMGREP_SEND_METRICS", "off");
            // 없으면 윈도우 기본 인코딩(cp949)으로 동작해 한글이 든 경로(C:\ai 과제\...)·규칙 메시지에서 실행 자체가 실패한다(실제로 그랬다).
            builder.environment().put("PYTHONUTF8", "1");
            builder.environment().put("PYTHONIOENCODING", "utf-8");
            // 진행 표시·경고가 많아 파이프로 받으면 버퍼가 차서 프로세스가 멈출 수 있다 — 파일로 받는다.
            builder.redirectErrorStream(true);
            builder.redirectOutput(logFile.toFile());

            Process process = start(builder);
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new SecureCodeScanException("코드 점검이 제한시간(" + timeoutSeconds + "초)을 넘겨 중단했습니다.", null);
            }
            // 0이 정상이다(--error를 주지 않아 탐지가 있어도 0). 그 외는 규칙 오류·실행 오류다.
            if (process.exitValue() != 0) {
                log.error("Semgrep 비정상 종료(exit={}):\n{}", process.exitValue(), tail(logFile));
                throw new SecureCodeScanException("Semgrep이 비정상 종료했습니다(exit=" + process.exitValue() + "). 서버 로그를 확인하세요.", null);
            }
            return Files.readString(output, StandardCharsets.UTF_8);
        } finally {
            Files.deleteIfExists(output);
            Files.deleteIfExists(logFile);
        }
    }

    /**
     * 기동할 때 Semgrep이 실행되는지·고정 버전과 같은지 확인해 로그로 알린다. 없으면 점검 버튼을 눌러야 비로소 알게 되는데,
     * 사람마다 로컬에서 서버를 띄우는 지금 구성에서는 "설치를 빠뜨린 PC"가 흔하다. 확인만 하고 기동을 막지는 않는다 —
     * 코드 점검은 부가 기능이라 없다고 라이브러리 스캔·화면까지 못 쓰게 할 이유가 없다. 파이썬을 띄우느라 몇 초 걸려 따로 돌린다.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void checkOnStartup() {
        Thread thread = new Thread(this::checkInstallation, "semgrep-check");
        thread.setDaemon(true);
        thread.start();
    }

    void checkInstallation() {
        String pinned = pinnedVersion();
        String install = "py -m pip install -r securecode/requirements.txt (저장소 루트에서)";
        try {
            ProcessBuilder builder = new ProcessBuilder(new ArrayList<>(List.of(command(), "--version", "--disable-version-check")));
            builder.environment().put("PYTHONUTF8", "1");
            builder.redirectErrorStream(true);
            Process process = start(builder);
            // 출력이 몇 줄뿐이라 파이프로 받아도 막히지 않는다.
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                log.warn("Semgrep 버전 확인 실패 — 코드 점검이 안 될 수 있습니다. 설치: {}", install);
                return;
            }
            Matcher matcher = VERSION.matcher(output);
            String installed = matcher.find() ? matcher.group(1) : "알 수 없음";
            if (pinned != null && !pinned.equals(installed)) {
                log.warn("Semgrep 버전이 고정 버전과 다릅니다(설치 {}, 고정 {}) — 탐지 결과가 다른 PC와 달라질 수 있습니다. 맞추기: {}",
                        installed, pinned, install);
            } else {
                log.info("Semgrep {} 확인 — 코드 점검 사용 가능", installed);
            }
        } catch (SecureCodeScanException e) {
            log.warn("Semgrep이 설치돼 있지 않아 코드 점검을 쓸 수 없습니다(다른 기능은 정상). 설치: {}", install);
        } catch (Exception e) {
            log.warn("Semgrep 설치 확인 중 오류(코드 점검이 안 될 수 있음): {}", e.toString());
        }
    }

    /** securecode/requirements.txt의 semgrep==버전. 파일이 없거나 형식이 다르면 null(버전 비교를 건너뛴다). */
    private String pinnedVersion() {
        try {
            Path requirements = Path.of(rulesDir).toAbsolutePath().normalize().getParent().resolve("requirements.txt");
            Matcher matcher = PINNED_VERSION.matcher(Files.readString(requirements, StandardCharsets.UTF_8));
            return matcher.find() ? matcher.group(1) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String command() {
        return discoveredCommand != null ? discoveredCommand : semgrepCommand;
    }

    /** 설정하지 않은 기본 명령이 PATH에 없으면 파이썬 Scripts 폴더에서 찾아 한 번 더 시도한다. 직접 설정한 경로는 그대로 실패시킨다. */
    private Process start(ProcessBuilder builder) throws InterruptedException {
        try {
            return builder.start();
        } catch (IOException first) {
            String found = DEFAULT_COMMAND.equals(semgrepCommand) && discoveredCommand == null ? findInPythonScripts() : null;
            if (found != null) {
                log.info("PATH에 semgrep이 없어 파이썬 Scripts 폴더의 실행 파일을 씁니다: {}", found);
                discoveredCommand = found;
                builder.command().set(0, found);
                try {
                    return builder.start();
                } catch (IOException second) {
                    first.addSuppressed(second);
                }
            }
            throw new SecureCodeScanException(
                    "Semgrep을 실행할 수 없습니다. 서버에 설치됐는지(py -m pip install -r securecode/requirements.txt), 설정 securecode.semgrep.command가 맞는지 확인하세요.", first);
        }
    }

    /** ai.python.command로 파이썬을 띄워 Scripts 폴더 위치를 묻는다. 못 찾으면 null. */
    private String findInPythonScripts() throws InterruptedException {
        try {
            Process python = new ProcessBuilder(pythonCommand, "-c", "import sysconfig;print(sysconfig.get_path('scripts'))")
                    .redirectErrorStream(true).start();
            // 출력이 한 줄이라 파이프로 받아도 막히지 않는다.
            String scriptsDir = new String(python.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!python.waitFor(10, TimeUnit.SECONDS) || python.exitValue() != 0 || scriptsDir.isEmpty()) {
                python.destroyForcibly();
                return null;
            }
            for (String name : List.of("semgrep.exe", "semgrep")) {
                Path candidate = Path.of(scriptsDir, name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toString();
                }
            }
            return null;
        } catch (IOException e) {
            log.warn("파이썬 Scripts 폴더에서 semgrep을 찾지 못함({}): {}", pythonCommand, e.toString());
            return null;
        }
    }

    private static String tail(Path logFile) {
        try {
            List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
            return String.join("\n", lines.subList(Math.max(0, lines.size() - 30), lines.size()));
        } catch (IOException e) {
            return "(로그를 읽지 못함: " + e.getMessage() + ")";
        }
    }
}
