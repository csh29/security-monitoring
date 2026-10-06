package com.sjinc.cvemonitor.service.securecode;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayAccessExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.Declaration;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.LocalDecl;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.ParamDecl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 점검 대상 저장소의 Java 소스를 읽어 trace-rules.yml 초안(세션 덮어쓰기 장치·로그인 정보 타입)을 만든다. 결정론이고 소스는 서버 밖으로
 * 나가지 않는다. 사람이 근거를 보고 확인해 trace-rules.yml에 반영한다 — 서버가 설정 파일을 직접 쓰지 않는다.
 *
 * <p>찾는 것:
 * <ul>
 *   <li>AOP 어드바이스({@code @Aspect} 클래스의 {@code @Before}/{@code @Around})의 포인트컷 {@code @annotation(X)} → 어노테이션,
 *       {@code args(request, ..)} → 첫 파라미터 조건</li>
 *   <li>어드바이스 본문에서 호출을 따라가며 요청 인자(또는 그 안의 {@code get("k")} 맵·맵 목록의 행)에 하는
 *       {@code put("key", 값)} 중 <b>값이 세션에서 온 것</b>만 → 덮어쓰는 키와 위치(container)</li>
 *   <li>{@code (T) session.getAttribute(...)}로 꺼내는 타입 T → 로그인 정보 타입, T의 getter 공통 접두어 → 로그인 getter 접두어</li>
 * </ul>
 * 세션 값이 아닌 put(예: 구문 id 앞 6자리)은 키에 넣지 않고 "세션 값 아님"으로 따로 보여준다 — 그 키를 덮어쓰기로 등록하면
 * 클라이언트가 바꿀 수 있는 값을 안전하다고 판정하게 된다.
 *
 * <p>XML로 설정한 AOP({@code <aop:config>}), 리플렉션, 요청을 감싸는 필터는 찾지 못한다 — 흔적이 보이면 안내만 남긴다.
 */
public final class TraceRuleDrafter {

    /** 초안 결과. */
    public record Draft(List<OverwriteCandidate> overwrites, List<Evidenced> loginTypeNames,
                        List<Evidenced> loginMethodPrefixes, List<String> notes, List<String> failedFiles) {
    }

    /**
     * 세션 덮어쓰기 후보 하나(어노테이션 + 위치). keys는 세션 값으로 덮어쓰는 키와 그 근거, nonSessionKeys는 같은 장치가
     * 넣지만 세션 값이 아닌 키(등록하면 안 됨).
     */
    public record OverwriteCandidate(String annotation, String container, String requiredFirstParam,
                                     List<Evidenced> keys, List<Evidenced> nonSessionKeys, List<String> evidence) {
    }

    /** 값 하나와 그 근거(파일:줄 코드). */
    public record Evidenced(String value, String evidence) {
    }

    private static final Set<String> ADVICE_ANNOTATIONS = Set.of("Before", "Around");
    private static final Pattern ANNOTATION_POINTCUT = Pattern.compile("@annotation\\(\\s*([\\w.$]+)\\s*\\)");
    private static final Pattern ARGS_POINTCUT = Pattern.compile("(?<![\\w@])args\\(([^)]*)\\)");
    private static final Pattern NAMED_POINTCUT = Pattern.compile("([A-Za-z_$][\\w$]*)\\(\\s*\\)");
    /** 어드바이스에서 따라가는 호출 깊이. 사내 프레임워크는 aspect → util → private 한두 단계가 보통이다. */
    private static final int MAX_DEPTH = 4;

    private final JavaSourceIndex java;
    private final Set<String> sessionTypes = new TreeSet<>();

    private TraceRuleDrafter(JavaSourceIndex java) {
        this.java = java;
    }

    /** @param sources 저장소 루트 기준 경로 → 내용(.java·.xml. MybatisDollarTracer.readSources와 같은 기준) */
    public static Draft draft(Map<String, String> sources) {
        Map<String, String> javaSources = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>();
        sources.forEach((path, content) -> {
            if (path.endsWith(".java")) javaSources.put(path, content);
            else if (path.endsWith(".xml") && content.contains("<aop:config")) {
                notes.add(path + " — XML로 설정한 AOP(<aop:config>)가 있습니다. 이 방식은 자동으로 찾지 못하니 직접 확인하세요.");
            }
        });
        JavaSourceIndex java = JavaSourceIndex.build(javaSources);
        return new TraceRuleDrafter(java).run(notes);
    }

    private Draft run(List<String> notes) {
        List<Evidenced> loginTypes = findSessionTypes();
        List<OverwriteCandidate> overwrites = new ArrayList<>();
        for (ClassOrInterfaceDeclaration type : java.allClasses()) {
            if (!JavaSourceIndex.hasAnnotation(type, "Aspect")) continue;
            for (MethodDeclaration advice : type.getMethods()) {
                for (AnnotationExpr annotation : advice.getAnnotations()) {
                    if (!ADVICE_ANNOTATIONS.contains(annotation.getNameAsString())) continue;
                    String pointcut = expandNamedPointcuts(type, pointcutOf(annotation));
                    if (pointcut == null) continue;
                    overwrites.addAll(candidates(advice, annotation, pointcut));
                }
            }
        }
        for (ClassOrInterfaceDeclaration type : java.allClasses()) {
            if (type.getExtendedTypes().stream().anyMatch(t -> t.getNameAsString().equals("HttpServletRequestWrapper"))) {
                notes.add(java.location(type) + " " + type.getNameAsString()
                        + " — 요청을 감싸는 래퍼가 있습니다. 필터가 요청 파라미터를 바꾸는 방식은 자동으로 찾지 못하니 직접 확인하세요.");
            }
        }
        if (overwrites.isEmpty()) {
            notes.add("세션 값을 요청 맵에 덮어쓰는 AOP를 찾지 못했습니다. 컨트롤러가 직접 put하는 방식이면 규칙 없이도 연계 추적이 따라갑니다.");
        }
        return new Draft(overwrites, loginTypes, loginMethodPrefixes(), notes, java.failedFiles());
    }

    // ---------------------------------------------------------------- YAML 초안

    /**
     * trace-rules.yml에 붙여 넣을 수 있는 초안. 근거는 주석으로 단다 — 사람이 파일만 보고도 왜 그 항목이 있는지 알 수 있게.
     * 세션 값이 아닌 키는 넣지 않고 주석으로만 남긴다. 키가 하나도 없거나 위치가 두 단계 이상(표현 불가)인 후보는 주석 처리한다.
     */
    public static String toYaml(Draft draft, String systemName) {
        StringBuilder y = new StringBuilder();
        y.append("# 추적 규칙 초안 — ").append(oneLine(systemName)).append(". 근거를 확인한 뒤 securecode/trace-rules.yml에 반영하세요.\n");
        y.append("sessionOverwrites:\n");
        if (draft.overwrites().isEmpty()) y.append("  # (찾은 장치 없음)\n");
        for (OverwriteCandidate c : draft.overwrites()) {
            boolean usable = !c.keys().isEmpty() && (c.container() == null || !c.container().contains("."));
            String p = usable ? "  " : "  # ";
            c.evidence().forEach(e -> y.append("  # 근거: ").append(oneLine(e)).append('\n'));
            c.keys().forEach(k -> y.append("  #   ").append(k.value()).append(" ← ").append(oneLine(k.evidence())).append('\n'));
            c.nonSessionKeys().forEach(k -> y.append("  # 세션 값이 아니라 넣지 않음: ").append(k.value())
                    .append(" ← ").append(oneLine(k.evidence())).append('\n'));
            if (!usable) {
                y.append("  # 아래 항목은 ").append(c.keys().isEmpty() ? "세션 값 키가 없어" : "위치가 두 단계 이상이라")
                        .append(" 그대로 쓸 수 없습니다 — 직접 확인하세요.\n");
            }
            y.append(p).append("- name: \"").append(oneLine(systemName + " @" + c.annotation()).replace("\"", "'")).append("\"\n");
            y.append(p).append("  annotation: ").append(c.annotation()).append('\n');
            if (c.container() != null) y.append(p).append("  container: ").append(c.container()).append('\n');
            if (c.requiredFirstParam() != null) y.append(p).append("  requiredFirstParam: ").append(c.requiredFirstParam()).append('\n');
            y.append(p).append("  keys: [").append(String.join(", ", c.keys().stream().map(Evidenced::value).toList())).append("]\n");
        }
        y.append('\n');
        draft.loginMethodPrefixes().forEach(e -> y.append("# 근거: ").append(oneLine(e.evidence())).append('\n'));
        y.append("loginMethodPrefixes: [").append(String.join(", ", draft.loginMethodPrefixes().stream().map(Evidenced::value).toList())).append("]\n\n");
        draft.loginTypeNames().forEach(e -> y.append("# 근거: ").append(oneLine(e.evidence())).append('\n'));
        y.append("loginTypeNames: [").append(String.join(", ", draft.loginTypeNames().stream().map(Evidenced::value).toList())).append("]\n");
        return y.toString();
    }

    private static String oneLine(String text) {
        return text == null ? "" : text.replaceAll("[\\r\\n]+", " ");
    }

    // ---------------------------------------------------------------- 로그인 정보 타입

    /** {@code (T) x.getAttribute(...)}에서 x가 세션(getSession() 결과·HttpSession 변수)인 T. */
    private List<Evidenced> findSessionTypes() {
        Map<String, String> found = new LinkedHashMap<>();
        for (MethodCallExpr call : java.callsNamed("getAttribute")) {
            if (!isSessionScope(call)) continue;
            Node parent = call.getParentNode().orElse(null);
            while (parent instanceof EnclosedExpr) parent = parent.getParentNode().orElse(null);
            if (parent instanceof CastExpr cast) {
                String type = JavaSourceIndex.simpleName(cast.getType());
                if (!type.equals("String") && !type.equals("Object")) {
                    sessionTypes.add(type);
                    found.putIfAbsent(type, java.location(cast) + " " + abbreviate(cast.toString()));
                }
            }
        }
        List<Evidenced> result = new ArrayList<>();
        found.forEach((type, evidence) -> result.add(new Evidenced(type, evidence)));
        return result;
    }

    private boolean isSessionScope(MethodCallExpr getAttribute) {
        Expression scope = getAttribute.getScope().orElse(null);
        if (scope == null) return false;
        if (scope instanceof MethodCallExpr call && call.getNameAsString().equals("getSession")) return true;
        return "HttpSession".equals(java.typeNameOf(scope));
    }

    /** 로그인 정보 타입의 getter 호출들의 공통 접두어(get 뒤 한 단어 이상일 때만 — "get"만이면 의미가 없다). */
    private List<Evidenced> loginMethodPrefixes() {
        Set<String> getters = new TreeSet<>();
        for (String type : sessionTypes) {
            for (ClassOrInterfaceDeclaration c : java.allClasses()) {
                if (!c.getNameAsString().equals(type)) continue;
                c.getMethods().stream().map(MethodDeclaration::getNameAsString)
                        .filter(n -> n.startsWith("get") && n.length() > 3).forEach(getters::add);
                // Lombok @Getter라 getter가 소스에 없으면 필드 이름으로 만든다.
                c.getFields().forEach(f -> f.getVariables().forEach(v ->
                        getters.add("get" + Character.toUpperCase(v.getNameAsString().charAt(0)) + v.getNameAsString().substring(1))));
            }
        }
        String prefix = commonCamelPrefix(getters);
        if (prefix == null || prefix.equals("get")) return List.of();
        return List.of(new Evidenced(prefix, String.join(", ", sessionTypes) + "의 getter " + getters.size() + "개 공통 접두어"));
    }

    /** 카멜 표기 단어 경계 기준 공통 접두어(getLoginCompCd, getLoginUserId → getLogin). */
    static String commonCamelPrefix(Set<String> names) {
        if (names.isEmpty()) return null;
        String prefix = null;
        for (String name : names) {
            prefix = prefix == null ? name : commonPrefix(prefix, name);
        }
        // 단어 중간에서 끊기면 단어 경계까지 줄인다(getLog|in 이 아니라 getLogin).
        int end = prefix.length();
        for (String name : names) {
            if (name.length() > end && !Character.isUpperCase(name.charAt(end))) {
                int i = end;
                while (i > 0 && !Character.isUpperCase(prefix.charAt(i - 1))) i--;
                end = Math.max(0, i - 1);
                break;
            }
        }
        return end <= 0 ? null : prefix.substring(0, end);
    }

    private static String commonPrefix(String a, String b) {
        int i = 0;
        while (i < a.length() && i < b.length() && a.charAt(i) == b.charAt(i)) i++;
        return a.substring(0, i);
    }

    // ---------------------------------------------------------------- AOP 포인트컷

    private static String pointcutOf(AnnotationExpr annotation) {
        if (annotation instanceof SingleMemberAnnotationExpr single && single.getMemberValue() instanceof StringLiteralExpr s) {
            return s.getValue();
        }
        if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if ((pair.getNameAsString().equals("value") || pair.getNameAsString().equals("pointcut"))
                        && pair.getValue() instanceof StringLiteralExpr s) {
                    return s.getValue();
                }
            }
        }
        return null;
    }

    /** {@code @Before("userInfo()")}처럼 같은 클래스의 {@code @Pointcut} 메서드를 부르면 그 식으로 바꾼다. */
    private static String expandNamedPointcuts(ClassOrInterfaceDeclaration type, String pointcut) {
        if (pointcut == null) return null;
        String expanded = pointcut;
        Matcher m = NAMED_POINTCUT.matcher(pointcut);
        while (m.find()) {
            String name = m.group(1);
            for (MethodDeclaration method : type.getMethodsByName(name)) {
                for (AnnotationExpr a : method.getAnnotations()) {
                    if (a.getNameAsString().equals("Pointcut")) {
                        String inner = pointcutOf(a);
                        if (inner != null) expanded = expanded.replace(name + "()", "(" + inner + ")");
                    }
                }
            }
        }
        return expanded;
    }

    private List<OverwriteCandidate> candidates(MethodDeclaration advice, AnnotationExpr adviceAnnotation, String pointcut) {
        Matcher annotationMatch = ANNOTATION_POINTCUT.matcher(pointcut);
        if (!annotationMatch.find()) return List.of();
        String annotation = annotationMatch.group(1);
        // @annotation(addUserInfo)처럼 어드바이스 파라미터 이름이면 그 파라미터의 타입이 어노테이션이다.
        for (Parameter p : advice.getParameters()) {
            if (p.getNameAsString().equals(annotation)) annotation = JavaSourceIndex.simpleName(p.getType());
        }
        annotation = annotation.substring(annotation.lastIndexOf('.') + 1);

        String requiredFirstParam = null;
        Matcher argsMatch = ARGS_POINTCUT.matcher(pointcut);
        if (argsMatch.find()) {
            String first = argsMatch.group(1).split(",")[0].trim();
            if (!first.isEmpty() && !first.equals("..") && !first.equals("*")) {
                requiredFirstParam = first.substring(first.lastIndexOf('.') + 1);
                for (Parameter p : advice.getParameters()) {
                    if (p.getNameAsString().equals(first)) requiredFirstParam = JavaSourceIndex.simpleName(p.getType());
                }
            }
        }

        // 어드바이스 본문부터 호출을 따라가며 요청 인자 기준 맵 경로에 하는 put을 모은다.
        Map<String, List<Evidenced>> sessionKeys = new LinkedHashMap<>();
        Map<String, List<Evidenced>> otherKeys = new LinkedHashMap<>();
        collectPuts(advice, Map.of(), 0, new LinkedHashSet<>(), sessionKeys, otherKeys);

        String adviceEvidence = java.location(adviceAnnotation) + " " + abbreviate(adviceAnnotation.toString());
        List<OverwriteCandidate> result = new ArrayList<>();
        Set<String> containers = new LinkedHashSet<>(sessionKeys.keySet());
        containers.addAll(otherKeys.keySet());
        for (String container : containers) {
            result.add(new OverwriteCandidate(annotation, container.isEmpty() ? null : container, requiredFirstParam,
                    dedupe(sessionKeys.getOrDefault(container, List.of())),
                    dedupe(otherKeys.getOrDefault(container, List.of())),
                    List.of(adviceEvidence)));
        }
        return result;
    }

    /**
     * method 안의 put을 모으고, 맵을 넘기는 우리 메서드 호출을 따라 들어간다.
     *
     * @param boundPaths 이 메서드 파라미터 이름 → 요청 인자 기준 맵 경로(호출자에서 넘겨준 인자가 요청 맵의 어디인지)
     */
    private void collectPuts(CallableDeclaration<?> method, Map<String, List<String>> boundPaths, int depth, Set<String> visiting,
                             Map<String, List<Evidenced>> sessionKeys, Map<String, List<Evidenced>> otherKeys) {
        String mark = System.identityHashCode(method) + ":" + boundPaths;
        if (depth > MAX_DEPTH || !visiting.add(mark)) return;
        for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
            if (call.getNameAsString().equals("put") && call.getArguments().size() == 2 && call.getScope().isPresent()
                    && unwrap(call.getArgument(0)) instanceof StringLiteralExpr key) {
                List<String> path = pathOf(call.getScope().get(), method, boundPaths, depth == 0, 0);
                if (path == null) continue;
                // 경로가 두 단계 이상(paramData.sub)이면 trace-rules.yml이 표현하지 못한다 — 점으로 이어 보여주고 사람이 판단한다.
                String container = String.join(".", path);
                Evidenced item = new Evidenced(key.getValue(), java.location(call) + " " + abbreviate(call.toString()));
                (isSessionValue(call.getArgument(1), method) ? sessionKeys : otherKeys)
                        .computeIfAbsent(container, k -> new ArrayList<>()).add(item);
                continue;
            }
            List<MethodDeclaration> callees = java.resolve(call);
            if (callees.isEmpty()) continue;
            for (MethodDeclaration callee : callees) {
                Map<String, List<String>> calleePaths = new HashMap<>();
                for (int i = 0; i < call.getArguments().size() && i < callee.getParameters().size(); i++) {
                    List<String> path = pathOf(call.getArgument(i), method, boundPaths, depth == 0, 0);
                    if (path != null) calleePaths.put(callee.getParameter(i).getNameAsString(), path);
                }
                if (!calleePaths.isEmpty()) {
                    collectPuts(callee, calleePaths, depth + 1, visiting, sessionKeys, otherKeys);
                }
            }
        }
        visiting.remove(mark);
    }

    /**
     * 식이 요청 인자(어드바이스가 받은 인자) 기준으로 어떤 맵 경로인가. 인자 자체면 [], {@code arg.get("paramData")}면 [paramData].
     * 맵 목록의 행({@code for (Map row : list)})은 목록과 같은 경로로 본다. 요청 인자와 무관하면 null.
     */
    private List<String> pathOf(Expression expression, CallableDeclaration<?> method, Map<String, List<String>> boundPaths,
                                boolean advice, int depth) {
        Expression e = unwrap(expression);
        if (depth > 12) return null;
        if (e instanceof MethodCallExpr call) {
            if (call.getNameAsString().equals("getArgs") && advice) return List.of(); // 어드바이스의 joinPoint.getArgs()
            if (call.getNameAsString().equals("get") && call.getArguments().size() == 1
                    && unwrap(call.getArgument(0)) instanceof StringLiteralExpr key && call.getScope().isPresent()) {
                List<String> base = pathOf(call.getScope().get(), method, boundPaths, advice, depth + 1);
                if (base == null) return null;
                List<String> path = new ArrayList<>(base);
                path.add(key.getValue());
                return path;
            }
            return null;
        }
        if (e instanceof ArrayAccessExpr access) {
            return pathOf(access.getName(), method, boundPaths, advice, depth + 1);
        }
        if (!(e instanceof NameExpr name)) return null;
        if (boundPaths.containsKey(name.getNameAsString())) {
            Declaration d = java.declarationOf(name).orElse(null);
            if (d instanceof ParamDecl p && p.callable() == method) return boundPaths.get(name.getNameAsString());
        }
        Declaration declaration = java.declarationOf(name).orElse(null);
        if (declaration instanceof ParamDecl param && advice && param.callable() == method) {
            // 어드바이스가 직접 받은 요청 인자(args(request, param)의 param). JoinPoint·요청·응답 객체는 빼고 맵 계열만.
            String type = JavaSourceIndex.simpleName(param.parameter().getType());
            if (type.endsWith("Map") || java.extendsAny(type, Set.of("Map", "HashMap", "LinkedHashMap"))) return List.of();
            return null;
        }
        if (declaration instanceof LocalDecl local) {
            ForEachStmt forEach = local.forEach();
            if (forEach != null) return pathOf(forEach.getIterable(), method, boundPaths, advice, depth + 1);
            return local.variable().getInitializer().map(init -> pathOf(init, method, boundPaths, advice, depth + 1)).orElse(null);
        }
        return null;
    }

    /** 값이 세션에서 온 것인가 — 세션 getAttribute 결과이거나, 로그인 정보 타입(세션에서 꺼낸 타입)의 getter. */
    private boolean isSessionValue(Expression expression, CallableDeclaration<?> method) {
        Expression e = unwrap(expression);
        if (e instanceof MethodCallExpr call) {
            if (call.getNameAsString().equals("getAttribute") && isSessionScope(call)) return true;
            Expression scope = call.getScope().orElse(null);
            if (scope == null) return false;
            String type = java.typeNameOf(scope);
            if (type != null && sessionTypes.contains(type)) return true;
            if (scope instanceof NameExpr n) {
                Declaration d = java.declarationOf(n).orElse(null);
                if (d instanceof LocalDecl local && local.variable().getInitializer().isPresent()) {
                    return isSessionValue(local.variable().getInitializer().get(), method);
                }
            }
            return isSessionValue(scope, method) && Set.of("toString", "trim").contains(call.getNameAsString());
        }
        return false;
    }

    private static List<Evidenced> dedupe(List<Evidenced> items) {
        Map<String, Evidenced> byValue = new LinkedHashMap<>();
        items.forEach(i -> byValue.putIfAbsent(i.value(), i));
        return new ArrayList<>(byValue.values());
    }

    private static Expression unwrap(Expression expression) {
        Expression e = expression;
        while (true) {
            if (e instanceof EnclosedExpr enclosed) e = enclosed.getInner();
            else if (e instanceof CastExpr cast) e = cast.getExpression();
            else return e;
        }
    }

    private static String abbreviate(String code) {
        String oneLine = code.replaceAll("\\s+", " ");
        return oneLine.length() > 140 ? oneLine.substring(0, 137) + "..." : oneLine;
    }
}
