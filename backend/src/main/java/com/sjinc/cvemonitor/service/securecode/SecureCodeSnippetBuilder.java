package com.sjinc.cvemonitor.service.securecode;

import com.sjinc.cvemonitor.dto.securecode.DetectedFinding;
import com.sjinc.cvemonitor.dto.securecode.SemgrepMatch;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Semgrep이 알려준 위치로 clone한 파일을 직접 읽어 코드 조각과 지문을 만든다. clone 디렉터리는 점검이 끝나면 지워지므로
 * 그 전에 부른다. Spring 없이 테스트할 수 있게 순수 클래스로 둔다.
 */
public class SecureCodeSnippetBuilder {

    /** 걸린 줄 앞뒤로 보여줄 줄 수. */
    static final int CONTEXT_LINES = 5;

    /** 한 줄이 이보다 길면 자른다 — 압축된 JS 한 줄이 수십 KB라 화면·DB를 채운다. */
    static final int MAX_LINE_LENGTH = 300;

    /** 사내 레거시 소스는 EUC-KR(MS949)로 저장된 경우가 많다. UTF-8로 읽다 깨지면 이걸로 다시 읽는다. */
    private static final Charset MS949 = Charset.forName("MS949");

    private static final Pattern STRING_LITERAL = Pattern.compile("\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'");
    private static final Pattern CONFIG_SECRET_LINE = Pattern.compile(
            "(?i)^(\\s*[\\w.\\-]*(?:password|passwd|secret|api[\\-_.]?key|access[\\-_.]?key|private[\\-_.]?key|token)[\\w.\\-]*\\s*[=:]\\s*).+$");
    /** 주석 안의 "password: 값" (kisa-hardcoded-secret-comment). 줄 앞이 주석 기호라 CONFIG_SECRET_LINE에 걸리지 않는다. */
    private static final Pattern COMMENT_SECRET = Pattern.compile(
            "(?i)((?://|#|<!--|/\\*|\\*)[^\\n]*?(?:password|passwd|pwd|비밀번호|비번|secret|api[\\-_.]?key|access[\\-_.]?key|token)[\\w.\\-]*\\s*[=:]\\s*)[^\\s'\"<>]+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final Path projectDir;
    private final Map<String, List<String>> linesByPath = new HashMap<>();

    public SecureCodeSnippetBuilder(Path projectDir) {
        this.projectDir = projectDir.toAbsolutePath().normalize();
    }

    /**
     * 같은 규칙이 같은 파일에서 내용이 똑같은 코드에 여러 번 걸리면(같은 줄의 ${} 두 개, 복사된 코드) 지문이 겹친다.
     * 파일 안 등장 순서를 지문에 넣어 구분한다 — Semgrep 결과 순서는 파일·위치 순이라 매번 같다.
     */
    public List<DetectedFinding> build(List<SemgrepMatch> matches) throws IOException {
        Map<String, Integer> occurrences = new HashMap<>();
        List<DetectedFinding> detected = new ArrayList<>();
        for (SemgrepMatch match : matches) {
            List<String> lines = readLines(match.filePath());
            boolean secret = isSecretRule(match.ruleId());

            String matchedCode = normalize(mask(slice(lines, match.startLine(), match.endLine()), secret));
            String key = match.ruleId() + "\n" + match.filePath() + "\n" + matchedCode;
            int occurrence = occurrences.merge(key, 1, Integer::sum) - 1;

            int snippetStart = Math.max(1, match.startLine() - CONTEXT_LINES);
            int snippetEnd = Math.min(lines.size(), match.endLine() + CONTEXT_LINES);
            String snippet = String.join("\n", mask(slice(lines, snippetStart, snippetEnd), secret));

            detected.add(new DetectedFinding(
                    fingerprint(key + "\n" + occurrence),
                    match.ruleId(), match.kisaCategory(), match.kisaName(), match.cwe(), match.severity(),
                    match.filePath(), match.startLine(), match.endLine(), match.message(),
                    snippet, snippetStart, null, null));
        }
        return detected;
    }

    /** 하드코드된 비밀값 규칙(kisa-hardcoded-secret-*)은 조각·지문 모두 값을 가린 뒤 쓴다. */
    static boolean isSecretRule(String ruleId) {
        return ruleId != null && ruleId.contains("hardcoded-secret");
    }

    /**
     * 비밀값을 가린다. 코드 조각이 DB에 그대로 남으면 우리 DB가 각 앱의 비밀번호 모음이 된다. 지문도 가린 코드로 만든다 —
     * 짧은 비밀번호가 든 줄의 해시는 대입으로 되돌릴 수 있고, 값만 바뀐 경우엔 같은 건으로 보는 게 맞다(오탐 판단 유지).
     */
    static List<String> mask(List<String> lines, boolean secret) {
        if (!secret) return lines;
        List<String> masked = new ArrayList<>(lines.size());
        for (String line : lines) {
            String replaced = STRING_LITERAL.matcher(line).replaceAll(m -> m.group().charAt(0) + "****" + m.group().charAt(0));
            replaced = CONFIG_SECRET_LINE.matcher(replaced).replaceAll("$1****");
            replaced = COMMENT_SECRET.matcher(replaced).replaceAll("$1****");
            masked.add(replaced);
        }
        return masked;
    }

    /** 공백·들여쓰기만 바뀐 경우(포매터 적용)는 같은 코드로 본다. */
    static String normalize(List<String> lines) {
        return WHITESPACE.matcher(String.join(" ", lines)).replaceAll(" ").trim();
    }

    static String fingerprint(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 1부터 세는 줄 번호 범위(양끝 포함). 파일이 그새 바뀌어 범위를 벗어나면 있는 만큼만. */
    private static List<String> slice(List<String> lines, int fromLine, int toLine) {
        int from = Math.max(0, fromLine - 1);
        int to = Math.min(lines.size(), Math.max(fromLine, toLine));
        if (from >= to) return List.of();
        return lines.subList(from, to).stream()
                .map(line -> line.length() > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) + " …" : line)
                .toList();
    }

    private List<String> readLines(String relativePath) throws IOException {
        List<String> cached = linesByPath.get(relativePath);
        if (cached != null) return cached;

        // Semgrep이 준 경로라도 저장소 밖을 가리키면 읽지 않는다. 저장소 안의 심볼릭 링크가 서버 파일을 가리킬 수 있어
        // 링크를 따라간 실제 경로로 비교한다(normalize만으로는 ../만 막는다).
        Path file = projectDir.resolve(relativePath).normalize();
        if (!Files.isRegularFile(file) || !file.toRealPath().startsWith(projectDir.toRealPath())) {
            linesByPath.put(relativePath, List.of());
            return List.of();
        }
        List<String> lines = decode(Files.readAllBytes(file)).lines().toList();
        linesByPath.put(relativePath, lines);
        return lines;
    }

    static String decode(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            return new String(bytes, MS949);
        }
    }
}
