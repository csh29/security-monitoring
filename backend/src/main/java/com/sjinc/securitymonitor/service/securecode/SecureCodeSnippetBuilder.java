package com.sjinc.securitymonitor.service.securecode;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.sjinc.securitymonitor.dto.securecode.AiRelatedCode;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import com.sjinc.securitymonitor.dto.securecode.TraceStepCode;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Semgrep이 알려준 위치로 clone한 파일을 직접 읽어 코드 조각과 지문을 만든다. clone 디렉터리는 점검이 끝나면 지워지므로
 * 그 전에 부른다. Spring 없이 테스트할 수 있게 순수 클래스로 둔다.
 */
public class SecureCodeSnippetBuilder {

    /** 감싼 메서드·매퍼 구문을 못 찾을 때 걸린 줄 앞뒤로 보여줄 줄 수. */
    static final int CONTEXT_LINES = 5;

    /**
     * 화면용 조각의 최대 줄 수. 조각은 걸린 줄을 감싼 메서드(매퍼 XML이면 구문)를 통째로 보여준다 — 앞뒤 5줄로는 요청값을 받는 줄과 SQL을 실행하는 줄이
     * 같은 메서드 안에 있어도 잘려, 연계 추적 근거가 가리키는 줄을 화면에서 볼 수 없었다. 긴 메서드는 이 길이만큼 걸린 줄 주변만.
     */
    static final int SNIPPET_MAX_LINES = 80;

    /** 연계 추적 근거 한 걸음마다 보여줄, 그 줄 앞뒤 줄 수. */
    static final int TRACE_CONTEXT_LINES = 3;

    /** 연계 추적 근거 한 걸음의 시작 "파일명:줄"(JavaSourceIndex.location·MybatisDollarTracer의 XML 걸음과 같은 모양). */
    private static final Pattern STEP_LOCATION = Pattern.compile("^([^\\s:/\\\\]+\\.(?:java|xml)):(\\d+)(?=\\s|$)");
    /** 매퍼 XML의 구문 태그(MyBatis·iBatis). */
    private static final Pattern XML_STATEMENT_OPEN = Pattern.compile("(?i)<(select|insert|update|delete|sql|statement|procedure)\\b");
    private static final Pattern XML_STATEMENT_CLOSE = Pattern.compile("(?i)</(select|insert|update|delete|sql|statement|procedure)\\s*>");

    /** 한 줄이 이보다 길면 자른다 — 압축된 JS 한 줄이 수십 KB라 화면·DB를 채운다. */
    static final int MAX_LINE_LENGTH = 300;

    /**
     * AI 판별 문맥의 최대 줄 수. 걸린 줄을 감싼 메서드를 통째로 보내는 게 기본인데(입력이 어디서 와서 어떻게 검증되는지가 대개
     * 그 메서드 안에 있다), 수백 줄짜리 서비스 메서드는 이 길이만큼 걸린 줄 주변만 보낸다 — 보내는 코드를 판별에 필요한 만큼으로 줄인다.
     */
    static final int AI_CONTEXT_MAX_LINES = 80;

    /** AI 판별 관련 코드(aiRelatedCode) — 메서드당 줄 수, 개수, 합계 줄 수. 입력 토큰이 탐지 메서드의 몇 배로 늘지 않게. */
    static final int RELATED_MAX_LINES = 40;
    static final int RELATED_MAX_ITEMS = 8;
    static final int RELATED_MAX_TOTAL_LINES = 240;
    /** 코드 안 비밀값 대입(password = "…", API_KEY = "…") — 이런 줄이 있는 메서드는 관련 코드로 보내지 않는다. */
    private static final Pattern SECRET_ASSIGNMENT = Pattern.compile(
            "(?i)[\\w.]*(?:password|passwd|pwd|secret|api_?key|access_?key|private_?key|token|credential)\\w*\\s*[=:,(]\\s*\"[^\"]+\"");

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

            int[] range = enclosingRange(match.filePath(), lines, match.startLine(), match.endLine());
            if (range == null) range = new int[]{match.startLine() - CONTEXT_LINES, match.endLine() + CONTEXT_LINES};
            range = cap(range, match.startLine(), Math.max(match.startLine(), match.endLine()), SNIPPET_MAX_LINES);
            int snippetStart = Math.max(1, range[0]);
            int snippetEnd = Math.min(lines.size(), range[1]);
            String snippet = String.join("\n", mask(slice(lines, snippetStart, snippetEnd), secret));

            detected.add(new DetectedFinding(
                    fingerprint(key + "\n" + occurrence),
                    match.ruleId(), match.kisaCategory(), match.kisaName(), match.cwe(), match.severity(),
                    match.filePath(), match.startLine(), match.endLine(), match.message(),
                    snippet, snippetStart, null, null, null, null).withColumns(match.startCol(), match.endCol()));
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
        int[] range = cap(method != null ? method : new int[]{start - AI_CONTEXT_LINES, end + AI_CONTEXT_LINES},
                start, end, AI_CONTEXT_MAX_LINES);
        int from = Math.max(1, range[0]);
        int to = Math.min(lines.size(), range[1]);
        String context = String.join("\n", mask(slice(lines, from, to), isSecretRule(finding.ruleId())));
        return finding.withAiContext(context, from);
    }

    /**
     * AI 판별에 탐지 메서드와 함께 보낼 다른 메서드들(2026-10-08). 메서드 하나만 보낼 때 AI가 값이 정해지는 다른 파일을 추측으로 채워 틀렸다
     * (OWASP Benchmark — 이름은 요청값 같지만 상수를 돌려주는 헬퍼를 "요청 파라미터"로 보고 확신도 high로 취약 판별). 순서대로:
     * <ol>
     *   <li>연계 추적 경로의 걸음이 있는 메서드(값이 지나온 컨트롤러·서비스)</li>
     *   <li>탐지 메서드가 부르는 우리 메서드(한 단계 — 값을 만드는 헬퍼)</li>
     * </ol>
     * <b>.java 메서드만</b> 보낸다 — properties·yml·xml 설정은 보내지 않는다. 비밀번호·키·토큰을 문자열로 대입하는 메서드는 통째로 뺀다
     * (가려서 보내는 대신 아예 안 보낸다 — 키 값을 담은 코드는 판별 근거로도 필요 없다). 보내기 직전 SecretMasker로 한 번 더 가린다.
     * 메서드당 RELATED_MAX_LINES 줄, 모두 합쳐 RELATED_MAX_ITEMS개·RELATED_MAX_TOTAL_LINES 줄까지.
     *
     * @param pathsByFileName 파일 이름 → 저장소 기준 경로들(연계 추적 근거는 파일 이름만 적는다)
     */
    public List<AiRelatedCode> aiRelatedCode(DetectedFinding finding, JavaSourceIndex java,
                                             Map<String, List<String>> pathsByFileName) throws IOException {
        if (finding.aiContext() == null || finding.aiContextStartLine() == null) return List.of();
        int mainFrom = finding.aiContextStartLine();
        int mainTo = mainFrom + finding.aiContext().split("\n", -1).length - 1;
        Map<String, AiRelatedCode> related = new LinkedHashMap<>();
        int[] total = {0};

        if (finding.traceEvidence() != null) {
            for (String step : finding.traceEvidence().split("\n")) {
                Matcher m = STEP_LOCATION.matcher(step);
                if (!m.find()) continue;
                String path = pickPath(m.group(1), finding.filePath(), pathsByFileName);
                if (path == null || !path.endsWith(".java")) continue;
                List<String> lines = readLines(path);
                int line = Integer.parseInt(m.group(2));
                int[] range = enclosingCallable(path, lines, line, line);
                if (range == null) continue;
                addRelated(related, total, path, lines, range, mainOverlap(finding, path, range, mainFrom, mainTo),
                        "연계 추적 경로: " + step.strip());
            }
        }
        if (java != null) {
            Optional<CallableDeclaration<?>> method = java.callableAt(finding.filePath(), finding.startLine());
            if (method.isPresent()) {
                for (MethodCallExpr call : method.get().findAll(MethodCallExpr.class)) {
                    for (MethodDeclaration callee : java.resolve(call)) {
                        String path = java.pathOf(callee);
                        if (path == null || callee.getRange().isEmpty() || callee == method.get()) continue;
                        int[] range = {callee.getRange().get().begin.line, callee.getRange().get().end.line};
                        String owner = callee.findAncestor(TypeDeclaration.class)
                                .map(t -> ((TypeDeclaration<?>) t).getNameAsString()).orElse("?");
                        addRelated(related, total, path, readLines(path), range, mainOverlap(finding, path, range, mainFrom, mainTo),
                                "탐지 메서드가 부르는 " + owner + "." + callee.getNameAsString() + "()");
                    }
                }
            }
        }
        return new ArrayList<>(related.values());
    }

    private static boolean mainOverlap(DetectedFinding finding, String path, int[] range, int mainFrom, int mainTo) {
        return path.equals(finding.filePath()) && range[0] <= mainTo && range[1] >= mainFrom;
    }

    private void addRelated(Map<String, AiRelatedCode> related, int[] total, String path, List<String> lines, int[] range,
                            boolean overlapsMain, String reason) {
        String key = path + ":" + range[0];
        if (overlapsMain || related.containsKey(key) || related.size() >= RELATED_MAX_ITEMS || lines.isEmpty()) return;
        if (path.startsWith("src/test/") || path.contains("/src/test/")) return;
        int to = Math.min(range[1], range[0] + RELATED_MAX_LINES - 1);
        to = Math.min(to, range[0] + (RELATED_MAX_TOTAL_LINES - total[0]) - 1);
        if (to < range[0]) return;
        List<String> body = slice(lines, range[0], range[1]);
        if (body.stream().anyMatch(l -> SECRET_ASSIGNMENT.matcher(l).find() || CONFIG_SECRET_LINE.matcher(l).find())) return;
        List<String> code = new ArrayList<>(slice(lines, range[0], to));
        if (to < range[1]) code.add("    // … (이하 " + (range[1] - to) + "줄 생략)");
        total[0] += code.size();
        related.put(key, new AiRelatedCode(path, range[0], String.join("\n", code), reason));
    }

    /**
     * 연계 추적 근거의 걸음마다 그 줄 주변 코드(점검 때만 만들 수 있다 — clone은 점검이 끝나면 지운다). 근거와 같은 순서로, 파일·줄이 없는 걸음
     * ("파라미터 없이 실행" 등)이나 파일을 하나로 정하지 못한 걸음은 null. 코드가 붙은 걸음이 하나도 없으면 null.
     *
     * @param pathsByFileName 파일 이름 → 저장소 기준 경로들. 근거는 파일 이름만 적으므로(화면에서 읽기 좋게) 여기서 경로로 되돌린다.
     */
    public List<TraceStepCode> traceCode(DetectedFinding finding, Map<String, List<String>> pathsByFileName) throws IOException {
        if (finding.traceEvidence() == null || finding.traceEvidence().isBlank()) return null;
        boolean secret = isSecretRule(finding.ruleId());
        List<TraceStepCode> steps = new ArrayList<>();
        boolean any = false;
        for (String step : finding.traceEvidence().split("\n")) {
            Matcher m = STEP_LOCATION.matcher(step);
            String path = m.find() ? pickPath(m.group(1), finding.filePath(), pathsByFileName) : null;
            List<String> lines = path == null ? List.of() : readLines(path);
            int line = path == null ? 0 : Integer.parseInt(m.group(2));
            if (lines.isEmpty() || line < 1 || line > lines.size()) {
                steps.add(null);
                continue;
            }
            int from = Math.max(1, line - TRACE_CONTEXT_LINES);
            int to = Math.min(lines.size(), line + TRACE_CONTEXT_LINES);
            steps.add(new TraceStepCode(path, line, from, String.join("\n", mask(slice(lines, from, to), secret))));
            any = true;
        }
        return any ? steps : null;
    }

    /**
     * 근거의 파일 이름을 경로로. 탐지 파일 자신이면 그것, 후보가 하나면 그것, 여럿이면 탐지 파일과 경로 앞부분이 가장 길게 겹치는 것
     * (같은 모듈일 가능성이 크다). 그래도 하나로 못 고르면 null — 엉뚱한 파일의 코드를 보여주지 않는다.
     */
    static String pickPath(String fileName, String findingPath, Map<String, List<String>> pathsByFileName) {
        if (findingPath.equals(fileName) || findingPath.endsWith("/" + fileName)) return findingPath;
        List<String> candidates = pathsByFileName.getOrDefault(fileName, List.of());
        if (candidates.size() == 1) return candidates.get(0);
        String best = null;
        int bestLength = -1;
        boolean tie = false;
        for (String candidate : candidates) {
            int common = commonPrefix(candidate, findingPath);
            if (common > bestLength) {
                best = candidate;
                bestLength = common;
                tie = false;
            } else if (common == bestLength) {
                tie = true;
            }
        }
        return tie ? null : best;
    }

    private static int commonPrefix(String a, String b) {
        int n = Math.min(a.length(), b.length()), i = 0;
        while (i < n && a.charAt(i) == b.charAt(i)) i++;
        return i;
    }

    /** 걸린 줄이 가운데 오게 범위를 max 줄로 자른다. 범위 끝에 닿으면 그만큼 앞으로 당긴다. */
    static int[] cap(int[] range, int start, int end, int max) {
        int from = range[0], to = range[1];
        if (to - from + 1 <= max) return new int[]{from, to};
        int before = Math.max(0, (max - (end - start + 1)) / 2);
        int newFrom = Math.max(from, start - before);
        int newTo = Math.min(to, newFrom + max - 1);
        return new int[]{Math.max(from, Math.min(newFrom, newTo - max + 1)), newTo};
    }

    /** 화면용 조각의 범위 — 자바면 감싼 메서드, 매퍼 XML이면 감싼 구문(select·insert…). 못 찾으면 null. */
    private int[] enclosingRange(String path, List<String> lines, int start, int end) {
        if (path.endsWith(".xml")) return enclosingXmlStatement(lines, start, end);
        return enclosingCallable(path, lines, start, end);
    }

    /** 걸린 줄을 감싼 매퍼 구문 태그의 줄 범위. 위로 올라가다 여는 태그보다 닫는 태그를 먼저 만나면 구문 밖이다. */
    static int[] enclosingXmlStatement(List<String> lines, int start, int end) {
        int open = -1;
        String tag = null;
        for (int i = Math.min(start, lines.size()); i >= 1; i--) {
            String line = lines.get(i - 1);
            Matcher o = XML_STATEMENT_OPEN.matcher(line);
            if (o.find()) {
                open = i;
                tag = o.group(1);
                break;
            }
            if (i < start && XML_STATEMENT_CLOSE.matcher(line).find()) return null;
        }
        if (open < 0) return null;
        for (int i = open; i <= lines.size(); i++) {
            Matcher c = XML_STATEMENT_CLOSE.matcher(lines.get(i - 1));
            while (c.find()) {
                if (c.group(1).equalsIgnoreCase(tag)) return i >= end ? new int[]{open, i} : null;
            }
        }
        return null;
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

    public static String decode(byte[] bytes) {
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
