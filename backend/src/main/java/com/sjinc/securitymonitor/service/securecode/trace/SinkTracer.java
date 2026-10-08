package com.sjinc.securitymonitor.service.securecode.trace;

import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.Declaration;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.LocalDecl;
import com.sjinc.securitymonitor.service.securecode.trace.ValueOriginTracer.Frame;
import com.sjinc.securitymonitor.service.securecode.trace.ValueOriginTracer.V;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;

/**
 * Semgrep이 "위험 호출 지점"으로 잡은 탐지(SSRF 변수 주소·명령 실행·파일 경로·업로드 저장·문자열 연결 SQL 등)에, 그 호출에 들어가는
 * 값(주소·명령·경로·SQL)이 어디서 오는지 판정을 붙인다. 무료판 Semgrep taint는 한 메서드 안만 봐서, 컨트롤러가 받은 값을 서비스에서
 * 쓰는 사내 구조에서는 이 지점들이 출처를 모르는 WARNING으로 남았다. ValueOriginTracer로 호출자를 거슬러 컨트롤러까지 따라간다.
 *
 * <p>어느 규칙을 추적할지·무엇을 따라갈지는 규칙 파일이 정한다(metadata.trace → TraceSink, RuleSetLoader가 읽음). 여기는 규칙을 모른다 —
 * 탐지 범위(줄·열)에 정확히 놓인 식을 찾아 선언대로 값을 꺼낸다. 실행 지점 규칙을 늘리거나 고칠 때 자바를 고치지 않는다.
 *
 * <p>등급은 TraceSafety.severity() — 클라이언트 값이면 HIGH로 올리고(확정), 서버 값·설정값이면 LOW, 끝까지 못 따라가면 MEDIUM.
 * 범위의 식을 찾지 못하면(열을 모르는 탐지, 파일을 구문 분석하지 못함) 판정을 붙이지 않는다(Semgrep 등급 그대로).
 */
public final class SinkTracer {

    /** 탐지 한 건의 판정. */
    public record SinkVerdict(String fingerprint, String ruleId, String path, int line, TraceSafety safety, List<String> evidence) {
    }

    /** 고정 호스트로 시작하는 주소("https://host/…"). 그 뒤에 요청값이 붙어도 호출 대상은 바뀌지 않는다(규칙의 sanitizer와 같은 기준). */
    private static final Pattern FIXED_HOST = Pattern.compile("^https?://[^/\\s]+/.*");

    private final JavaSourceIndex java;
    private final ValueOriginTracer origin;
    private final Map<String, TraceSink> sinks;

    /** @param sinks 연계 추적을 받는 규칙 id → 따라갈 값(RuleSetLoader.RuleSet.sinks) */
    public SinkTracer(JavaSourceIndex java, TraceRules rules, Map<String, TraceSink> sinks) {
        this.java = java;
        this.origin = new ValueOriginTracer(java, rules);
        this.sinks = sinks;
    }

    /** 탐지들 중 추적할 수 있는 것마다 판정. 범위의 식을 찾지 못한 탐지는 결과에 없다. */
    public List<SinkVerdict> trace(List<DetectedFinding> detected) {
        List<SinkVerdict> verdicts = new ArrayList<>();
        for (DetectedFinding f : detected) {
            TraceSink sink = sinks.get(f.ruleId());
            if (sink == null) continue;
            Expression at = java.expressionAt(f.filePath(), f.startLine(), f.startCol(), f.endLine(), f.endCol()).orElse(null);
            List<Expression> values = at == null ? List.of() : valuesOf(at, sink.target());
            CallableDeclaration<?> method = at == null ? null : at.findAncestor(CallableDeclaration.class).orElse(null);
            if (values.isEmpty() || method == null) continue;
            V worst = null;
            for (Expression value : values) {
                origin.resetBudget();
                V v = sink.fixedHost() && fixedHost(value) != null
                        ? V.of(TraceSafety.SERVER_SET, java.location(value) + " 호스트 고정: " + fixedHost(value))
                        : origin.valueOf(value, Frame.root(method), 0);
                if (worst == null || v.safety().worseThan(worst.safety())) worst = v;
            }
            verdicts.add(new SinkVerdict(f.fingerprint(), f.ruleId(), f.filePath(), f.startLine(), worst.safety(),
                    worst.append(java.location(at) + " " + ValueOriginTracer.abbreviate(at.toString())).evidence()));
        }
        return verdicts;
    }

    /** 걸린 식에서 따라갈 값 — 호출·생성이 아니면 인자를 꺼낼 수 없어 빈 목록(ARGUMENTS·FIRST_ARGUMENT). */
    private static List<Expression> valuesOf(Expression at, TraceSink.Target target) {
        if (target == TraceSink.Target.VALUE) return List.of(at);
        List<Expression> arguments = at instanceof MethodCallExpr m ? m.getArguments()
                : at instanceof ObjectCreationExpr c ? c.getArguments() : List.of();
        if (arguments.isEmpty()) return List.of();
        return target == TraceSink.Target.FIRST_ARGUMENT ? List.of(arguments.get(0)) : List.copyOf(arguments);
    }

    /** 판정을 탐지에 붙이고 등급을 다시 매긴다. 지문은 그대로다(재점검 비교·처리여부 유지). */
    public static List<DetectedFinding> apply(List<DetectedFinding> detected, List<SinkVerdict> verdicts) {
        Map<String, SinkVerdict> byFingerprint = new HashMap<>();
        verdicts.forEach(v -> byFingerprint.put(v.fingerprint(), v));
        List<DetectedFinding> result = new ArrayList<>(detected.size());
        for (DetectedFinding f : detected) {
            SinkVerdict v = byFingerprint.get(f.fingerprint());
            result.add(v == null ? f : f.withTrace(v.safety().severity(), v.safety().name(), String.join("\n", v.evidence())));
        }
        return result;
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
