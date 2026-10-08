package com.sjinc.securitymonitor.service.securecode.semgrep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import com.sjinc.securitymonitor.dto.securecode.SemgrepReport;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Semgrep {@code --json} 결과를 해석한다. Spring 없이 테스트할 수 있게 순수 클래스로 둔다.
 *
 * <p>무료판 Semgrep은 결과의 코드 줄({@code extra.lines})과 지문({@code extra.fingerprint})에 실제 값 대신
 * {@code "requires login"}을 넣는다(1.178.0에서 확인). 그래서 여기서는 위치만 받고, 코드 조각과 지문은
 * SecureCodeSnippetBuilder가 clone한 파일을 직접 읽어 만든다.
 */
@Slf4j
public class SemgrepReportParser {

    private final ObjectMapper objectMapper;

    public SemgrepReportParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public SemgrepReport parse(String json) throws IOException {
        JsonNode root = objectMapper.readTree(json);

        List<SemgrepMatch> matches = new ArrayList<>();
        for (JsonNode result : root.path("results")) {
            JsonNode extra = result.path("extra");
            JsonNode metadata = extra.path("metadata");
            matches.add(new SemgrepMatch(
                    ruleId(result.path("check_id").asText()),
                    textOrNull(metadata, "kisa_category"),
                    textOrNull(metadata, "kisa_name"),
                    textOrNull(metadata, "cwe"),
                    severity(extra.path("severity").asText(null)),
                    normalizePath(result.path("path").asText()),
                    result.path("start").path("line").asInt(),
                    result.path("end").path("line").asInt(),
                    textOrNull(extra, "message"),
                    result.path("start").path("col").asInt(),
                    result.path("end").path("col").asInt()));
        }

        // 해석 실패·시간 초과는 파일 단위로 errors에 온다. 경로가 없는 오류(규칙 문제 등)는 파일로 셀 수 없어 로그만 남긴다.
        Set<String> failedFiles = new TreeSet<>();
        for (JsonNode error : root.path("errors")) {
            String path = textOrNull(error, "path");
            if (path != null) {
                failedFiles.add(normalizePath(path));
            } else {
                log.warn("Semgrep 경로 없는 오류: type={}, message={}",
                        error.path("type").asText(), error.path("message").asText());
            }
        }

        return new SemgrepReport(matches, failedFiles, root.path("paths").path("scanned").size(),
                textOrNull(root, "version"));
    }

    /**
     * Semgrep은 규칙 id 앞에 설정 파일 경로를 점으로 이어 붙인다(예: {@code C.ai.cve-monitoring.securecode.rules.kisa-xss}).
     * 서버마다 규칙 폴더 위치가 달라도 같은 규칙이 같은 id가 되도록 마지막 조각만 쓴다 — 우리 규칙 id에는 점이 없다.
     */
    static String ruleId(String checkId) {
        int dot = checkId.lastIndexOf('.');
        return dot < 0 ? checkId : checkId.substring(dot + 1);
    }

    /** 윈도우에서는 경로가 역슬래시로 온다. 지문·화면 표시가 OS마다 달라지지 않게 /로 맞춘다. */
    static String normalizePath(String path) {
        String normalized = path.replace('\\', '/');
        return normalized.startsWith("./") ? normalized.substring(2) : normalized;
    }

    /** 공통코드 SEVERITY 값으로 바꾼다 — 화면의 심각도 뱃지·조회조건을 취약점 관리와 같이 쓰기 위함. */
    static String severity(String semgrepSeverity) {
        if (semgrepSeverity == null) return null;
        return switch (semgrepSeverity) {
            case "ERROR" -> "HIGH";
            case "WARNING" -> "MEDIUM";
            case "INFO" -> "LOW";
            default -> semgrepSeverity;
        };
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }
}
