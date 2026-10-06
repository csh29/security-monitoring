package com.sjinc.securitymonitor.service.securecode;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.service.securecode.JavaSourceIndex.Declaration;
import com.sjinc.securitymonitor.service.securecode.JavaSourceIndex.LocalDecl;
import com.sjinc.securitymonitor.service.securecode.ValueOriginTracer.Frame;
import com.sjinc.securitymonitor.service.securecode.ValueOriginTracer.V;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Semgrep이 "위험 호출 지점"으로만 잡은 탐지(SSRF 변수 주소·명령 실행·다운로드 경로·업로드 저장·문자열 연결 SQL)에, 그 호출에 들어가는
 * 값(주소·명령·경로·SQL)이 어디서 오는지 판정을 붙인다. 무료판 Semgrep taint는 한 메서드 안만 봐서, 컨트롤러가 받은 값을 서비스에서
 * 쓰는 사내 구조에서는 이 지점들이 출처를 모르는 WARNING으로 남았다. ValueOriginTracer로 호출자를 거슬러 컨트롤러까지 따라간다.
 *
 * <p>등급은 TraceSafety.severity() — 클라이언트 값이면 HIGH로 올리고(확정), 서버 값·설정값이면 LOW, 끝까지 못 따라가면 MEDIUM.
 * 탐지 줄에서 규칙이 보는 호출을 구문 트리로 다시 찾고, 못 찾으면 판정을 붙이지 않는다(Semgrep 등급 그대로).
 */
public final class SinkTracer {

    /** 탐지 한 건의 판정. 같은 줄에 같은 규칙 호출이 여럿이면 가장 위험한 것. */
    public record SinkVerdict(String ruleId, String path, int line, TraceSafety safety, List<String> evidence) {
    }

    /** 규칙 하나가 보는 호출 모양과, 그 호출에서 출처를 따라갈 인자. 못 알아보는 노드면 null. */
    private record SinkRule(String ruleId, Function<Node, List<Expression>> arguments, boolean hostMatters) {
    }

    private static final Set<String> REST_METHODS = Set.of("getForObject", "getForEntity", "postForObject", "postForEntity",
            "postForLocation", "exchange", "execute", "put", "delete", "patchForObject", "headForHeaders", "optionsForAllow");
    private static final Set<String> SQL_EXEC_METHODS = Set.of("executeQuery", "executeUpdate", "execute", "addBatch",
            "prepareStatement", "prepareCall", "createQuery", "createNativeQuery", "createSQLQuery", "query", "queryForObject",
            "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate");
    /** 고정 호스트로 시작하는 주소("https://host/…"). 그 뒤에 요청값이 붙어도 호출 대상은 바뀌지 않는다(규칙의 sanitizer와 같은 기준). */
    private static final Pattern FIXED_HOST = Pattern.compile("^https?://[^/\\s]+/.*");

    private static final List<SinkRule> RULES = List.of(
            new SinkRule("kisa-ssrf-dynamic-url", node -> {
                if (node instanceof ObjectCreationExpr c && c.getType().getNameAsString().equals("URL") && c.getArguments().size() == 1) {
                    return List.of(c.getArgument(0));
                }
                if (node instanceof MethodCallExpr m && REST_METHODS.contains(m.getNameAsString()) && !m.getArguments().isEmpty()) {
                    return List.of(m.getArgument(0));
                }
                return null;
            }, true),
            new SinkRule("kisa-os-command-exec", node -> {
                if (node instanceof MethodCallExpr m && (m.getNameAsString().equals("exec") || m.getNameAsString().equals("command"))) {
                    return List.copyOf(m.getArguments());
                }
                if (node instanceof ObjectCreationExpr c && c.getType().getNameAsString().equals("ProcessBuilder")) {
                    return List.copyOf(c.getArguments());
                }
                return null;
            }, false),
            new SinkRule("kisa-path-traversal-download", SinkTracer::pathArguments, false),
            new SinkRule("kisa-file-upload-save", node -> {
                if (node instanceof MethodCallExpr m) {
                    String name = m.getNameAsString();
                    if ((name.equals("transferTo") || name.equals("write")) && m.getArguments().size() == 1) return List.of(m.getArgument(0));
                    if (name.equals("copy") && m.getArguments().size() >= 2) return List.of(m.getArgument(1));
                }
                return null;
            }, false),
            new SinkRule("kisa-sql-injection-java-concat", node -> {
                if (node instanceof MethodCallExpr m && SQL_EXEC_METHODS.contains(m.getNameAsString()) && !m.getArguments().isEmpty()) {
                    return List.of(m.getArgument(0));
                }
                return null;
            }, false));

    private static final Map<String, SinkRule> RULES_BY_ID = new HashMap<>();

    static {
        RULES.forEach(r -> RULES_BY_ID.put(r.ruleId(), r));
    }

    private final JavaSourceIndex java;
    private final ValueOriginTracer origin;

    SinkTracer(JavaSourceIndex java, TraceRules rules) {
        this.java = java;
        this.origin = new ValueOriginTracer(java, rules);
    }

    /** 이 규칙의 탐지를 추적할 수 있는가. */
    public static boolean supports(String ruleId) {
        return RULES_BY_ID.containsKey(ruleId);
    }

    /** 탐지들 중 추적할 수 있는 것마다 판정. 호출을 찾지 못한 탐지는 결과에 없다. */
    List<SinkVerdict> trace(List<DetectedFinding> detected) {
        Map<String, SinkVerdict> byKey = new LinkedHashMap<>();
        for (DetectedFinding f : detected) {
            SinkRule rule = RULES_BY_ID.get(f.ruleId());
            String key = f.ruleId() + "|" + f.filePath() + "|" + f.startLine();
            if (rule == null || byKey.containsKey(key)) continue;
            V worst = null;
            Node sinkNode = null;
            for (Node node : java.nodesAt(f.filePath(), f.startLine())) {
                List<Expression> args = rule.arguments().apply(node);
                if (args == null || args.isEmpty()) continue;
                CallableDeclaration<?> method = node.findAncestor(CallableDeclaration.class).orElse(null);
                if (method == null) continue;
                for (Expression arg : args) {
                    origin.resetBudget();
                    V v = rule.hostMatters() && fixedHost(arg) != null
                            ? V.of(TraceSafety.SERVER_SET, java.location(arg) + " 호스트 고정: " + fixedHost(arg))
                            : origin.valueOf(arg, Frame.root(method), 0);
                    if (worst == null || v.safety().worseThan(worst.safety())) {
                        worst = v;
                        sinkNode = node;
                    }
                }
            }
            if (worst != null) {
                byKey.put(key, new SinkVerdict(f.ruleId(), f.filePath(), f.startLine(), worst.safety(),
                        worst.append(java.location(sinkNode) + " " + ValueOriginTracer.abbreviate(sinkNode.toString())).evidence()));
            }
        }
        return new ArrayList<>(byKey.values());
    }

    /** 판정을 탐지에 붙이고 등급을 다시 매긴다. 지문은 그대로다(재점검 비교·처리여부 유지). */
    static List<DetectedFinding> apply(List<DetectedFinding> detected, List<SinkVerdict> verdicts) {
        Map<String, SinkVerdict> byKey = new HashMap<>();
        verdicts.forEach(v -> byKey.put(v.ruleId() + "|" + v.path() + "|" + v.line(), v));
        List<DetectedFinding> result = new ArrayList<>(detected.size());
        for (DetectedFinding f : detected) {
            SinkVerdict v = byKey.get(f.ruleId() + "|" + f.filePath() + "|" + f.startLine());
            result.add(v == null ? f : f.withTrace(v.safety().severity(), v.safety().name(), String.join("\n", v.evidence())));
        }
        return result;
    }

    private static List<Expression> pathArguments(Node node) {
        if (node instanceof ObjectCreationExpr c && Set.of("File", "FileInputStream").contains(c.getType().getNameAsString())
                && !c.getArguments().isEmpty()) {
            return List.copyOf(c.getArguments());
        }
        if (node instanceof MethodCallExpr m && !m.getArguments().isEmpty()
                && ((m.getNameAsString().equals("get") && m.getScope().map(s -> s.toString().equals("Paths")).orElse(false))
                || (m.getNameAsString().equals("newInputStream") && m.getScope().map(s -> s.toString().equals("Files")).orElse(false)))) {
            return m.getNameAsString().equals("get") ? List.copyOf(m.getArguments()) : List.of(m.getArgument(0));
        }
        return null;
    }

    /**
     * 주소가 고정 호스트로 시작하면 그 앞부분(아니면 null). 지역 변수에 한 번 만든 주소({@code String url = BASE + "/v1?q=" + q})도 따라간다.
     * 상수 + "/..." 또는 "https://host/..."로 시작하면 고정이다. 상수 + 값은 값이 "@evil.com"이면 호스트가 바뀌어 고정이 아니다.
     */
    private String fixedHost(Expression expression) {
        Expression e = ValueOriginTracer.unwrap(expression);
        if (e instanceof NameExpr name) {
            Declaration d = java.declarationOf(name).orElse(null);
            if (d instanceof LocalDecl local && local.forEach() == null && local.variable().getInitializer().isPresent()
                    && local.callable().findAll(com.github.javaparser.ast.expr.AssignExpr.class).stream()
                    .noneMatch(a -> a.getTarget() instanceof NameExpr t && t.getNameAsString().equals(name.getNameAsString()))) {
                return fixedHost(local.variable().getInitializer().get());
            }
            return null;
        }
        List<Expression> operands = new ArrayList<>();
        flatten(e, operands);
        if (operands.size() < 2) return null;
        StringBuilder prefix = new StringBuilder();
        for (Expression operand : operands) {
            String constant = origin.constantString(operand);
            if (constant == null) break;
            prefix.append(constant);
        }
        return FIXED_HOST.matcher(prefix).matches() ? prefix.toString() : null;
    }

    private static void flatten(Expression expression, List<Expression> operands) {
        Expression e = ValueOriginTracer.unwrap(expression);
        if (e instanceof BinaryExpr b && b.getOperator() == BinaryExpr.Operator.PLUS) {
            flatten(b.getLeft(), operands);
            flatten(b.getRight(), operands);
        } else {
            operands.add(e);
        }
    }
}
