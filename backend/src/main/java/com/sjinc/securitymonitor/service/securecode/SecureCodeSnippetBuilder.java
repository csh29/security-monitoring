package com.sjinc.securitymonitor.service.securecode;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;

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
import java.util.Optional;
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

    /**
     * AI 판별 문맥의 최대 줄 수. 걸린 줄을 감싼 메서드를 통째로 보내는 게 기본인데(입력이 어디서 와서 어떻게 검증되는지가 대개
     * 그 메서드 안에 있다), 수백 줄짜리 서비스 메서드는 이 길이만큼 걸린 줄 주변만 보낸다 — 보내는 코드를 판별에 필요한 만큼으로 줄인다.
     */
    static final int AI_CONTEXT_MAX_LINES = 80;

    /** 감싼 메서드가 없을 때(자바가 아닌 파일, 구문 오류, 필드 초기화식) 걸린 줄 앞뒤로 보낼 줄 수. */
    static final int AI_CONTEXT_LINES = 15;

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
    private final Map<String, Optional<CompilationUnit>> unitsByPath = new HashMap<>();

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
                    snippet, snippetStart, null, null, null, null));
        }
        return detected;
    }

    /**
     * AI 판별에 보낼 코드 문맥을 붙인다. clone이 지워지기 전에, AI 판별 대상인 탐지에만 부른다(SecureCodeScanService).
     * 화면용 조각(앞뒤 5줄)으로는 입력이 어디서 오는지·어디서 검증하는지가 잘려서 AI가 판단할 근거가 없다.
     * 비밀값 규칙은 조각과 같은 기준으로 가린다. 그 밖의 비밀값은 AI로 보내기 직전에 한 번 더 가린다(SecureCodeAiReviewService).
     */
    public DetectedFinding withAiContext(DetectedFinding finding) throws IOException {
        List<String> lines = readLines(finding.filePath());
        if (lines.isEmpty()) return finding;
        int start = finding.startLine(), end = Math.max(finding.startLine(), finding.endLine());

        int[] method = enclosingCallable(finding.filePath(), lines, start, end);
        int from = method != null ? method[0] : start - AI_CONTEXT_LINES;
        int to = method != null ? method[1] : end + AI_CONTEXT_LINES;
        if (to - from + 1 > AI_CONTEXT_MAX_LINES) {
            // 걸린 줄이 가운데 오게 자른다. 메서드 끝에 닿으면 그만큼 앞으로 당긴다.
            int before = Math.max(0, (AI_CONTEXT_MAX_LINES - (end - start + 1)) / 2);
            int newFrom = Math.max(from, start - before);
            int newTo = Math.min(to, newFrom + AI_CONTEXT_MAX_LINES - 1);
            from = Math.max(from, Math.min(newFrom, newTo - AI_CONTEXT_MAX_LINES + 1));
            to = newTo;
        }
        from = Math.max(1, from);
        to = Math.min(lines.size(), to);
        String context = String.join("\n", mask(slice(lines, from, to), isSecretRule(finding.ruleId())));
        return finding.withAiContext(context, from);
    }

    /** 걸린 줄을 감싼 가장 안쪽 메서드·생성자의 줄 범위. 자바가 아니거나 구문 분석에 실패하면 null. */
    private int[] enclosingCallable(String path, List<String> lines, int start, int end) {
        if (!path.endsWith(".java")) return null;
        Optional<CompilationUnit> unit = unitsByPath.computeIfAbsent(path, k -> {
            ParseResult<CompilationUnit> result = new JavaParser(new ParserConfiguration()
                    .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)
                    .setAttributeComments(false)).parse(String.join("\n", lines));
            return result.getResult();
        });
        int[] best = null;
        for (CallableDeclaration<?> callable : unit.map(u -> u.findAll(CallableDeclaration.class)).orElse(List.of())) {
            if (callable.getRange().isEmpty()) continue;
            int from = callable.getRange().get().begin.line, to = callable.getRange().get().end.line;
            if (from <= start && to >= end && (best == null || to - from < best[1] - best[0])) {
                best = new int[]{from, to};
            }
        }
        return best;
    }

    /** 하드코드된 비밀값 규칙(kisa-hardcoded-secret-*)은 조각·지문 모두 값을 가린 뒤 쓴다. */
    public static boolean isSecretRule(String ruleId) {
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
