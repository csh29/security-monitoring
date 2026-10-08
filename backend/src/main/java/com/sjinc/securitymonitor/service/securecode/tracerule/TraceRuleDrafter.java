package com.sjinc.securitymonitor.service.securecode.tracerule;

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
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.Declaration;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.LocalDecl;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.ParamDecl;

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
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex;
import com.sjinc.securitymonitor.service.securecode.trace.MapperXmlIndex;

/**
 * 점검 대상 저장소의 Java 소스와 설정 파일을 읽어 trace-rules.yml 초안(세션 덮어쓰기 장치·로그인 정보 타입·사용자 범위 키 후보·프레임워크 구조)을
 * 만든다. 결정론이고 소스는 서버 밖으로 나가지 않는다. 초안을 지금 설정과 비교해 무엇을 바로 반영하고 무엇을 사람에게 묻는지는
 * TraceRuleChangePlanner가 정한다 — 판정을 느슨하게 만드는 항목은 사람이 근거를 보고 반영한다.
 *
 * <p>찾는 것:
 * <ul>
 *   <li>AOP 어드바이스({@code @Aspect} 클래스의 {@code @Before}/{@code @Around}, 그리고 XML {@code <aop:config>}의 before·around —
 *       FrameworkProfiler.xmlAdvices)의 포인트컷 {@code @annotation(X)} → 어노테이션, {@code args(request, ..)} → 첫 파라미터 조건</li>
 *   <li>어드바이스 본문에서 호출을 따라가며 요청 인자(또는 그 안의 {@code get("k")} 맵·맵 목록의 행)에 하는
 *       {@code put("key", 값)} 중 <b>값이 세션에서 온 것</b>만 → 덮어쓰는 키와 위치(container)</li>
 *   <li>{@code (T) session.getAttribute(...)}로 꺼내는 타입 T → 로그인 정보 타입, T의 getter 공통 접두어 → 로그인 getter 접두어</li>
 *   <li>위 장치가 세션 값으로 넣는 키, 그리고 서비스 코드가 로그인 정보로 직접 넣는 키({@code param.put("compCd", user.getLoginCompCd())})
 *       중 매퍼 SQL의 조건 자리(WHERE·ON·HAVING)에 쓰이는 것 → 사용자 범위 키 후보</li>
 *   <li>설정 파일·소스의 프레임워크 구조(FrameworkProfiler.profile) — 판정에는 쓰지 않는 기록</li>
 * </ul>
 * 세션 값이 아닌 put(예: 구문 id 앞 6자리)은 키에 넣지 않고 "세션 값 아님"으로 따로 보여준다 — 그 키를 덮어쓰기로 등록하면
 * 클라이언트가 바꿀 수 있는 값을 안전하다고 판정하게 된다.
 *
 * <p>리플렉션, 요청을 감싸는 필터는 찾지 못한다 — 흔적이 보이면 안내만 남긴다.
 */
public final class TraceRuleDrafter {

    /**
     * 초안 결과.
     *
     * @param scopeKeys 사용자 범위 키 후보 — 세션 덮어쓰기 장치나 서비스 코드가 로그인 정보로 넣는 키 중 매퍼 SQL 조건 자리에 쓰인 것
     *                  (근거는 그 SQL 위치, 서비스가 넣는 키면 넣는 줄도)
     * @param framework 프레임워크 구조 기록(판정에는 쓰지 않는다)
     */
    public record Draft(List<OverwriteCandidate> overwrites, List<Evidenced> loginTypeNames,
                        List<Evidenced> loginMethodPrefixes, List<Evidenced> scopeKeys,
                        List<TraceRules.FrameworkFact> framework, List<String> notes, List<String> failedFiles) {
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
        return draft(sources, JavaSourceIndex.fromSources(sources));
    }

    /** 이미 만든 Java 색인을 쓴다(점검 중 연계 추적과 같은 색인). */
    static Draft draft(Map<String, String> sources, JavaSourceIndex java) {
        return new TraceRuleDrafter(java).run(sources, new ArrayList<>());
    }

    private Draft run(Map<String, String> sources, List<String> notes) {
        List<Evidenced> loginTypes = findSessionTypes();
        List<OverwriteCandidate> overwrites = new ArrayList<>();
        for (ClassOrInterfaceDeclaration type : java.allClasses()) {
            if (!JavaSourceIndex.hasAnnotation(type, "Aspect")) continue;
            for (MethodDeclaration advice : type.getMethods()) {
                for (AnnotationExpr annotation : advice.getAnnotations()) {
                    if (!ADVICE_ANNOTATIONS.contains(annotation.getNameAsString())) continue;
                    String pointcut = expandNamedPointcuts(type, pointcutOf(annotation));
                    if (pointcut == null) continue;
                    overwrites.addAll(candidates(advice, pointcut, java.location(annotation) + " " + abbreviate(annotation.toString())));
                }
            }
        }
        // 옛 Spring XML 시스템은 애스펙트를 XML로 건다 — 어드바이스 메서드를 소스에서 찾아 같은 방법으로 따라간다.
        for (FrameworkProfiler.XmlAdvice xml : FrameworkProfiler.xmlAdvices(sources)) {
            List<MethodDeclaration> methods = java.allClasses().stream()
                    .filter(c -> c.getNameAsString().equals(xml.aspectClass()))
                    .flatMap(c -> c.getMethodsByName(xml.method()).stream())
                    .filter(m -> m.getBody().isPresent())
                    .toList();
            if (methods.isEmpty()) {
                notes.add(xml.evidence() + " — 어드바이스 메서드(" + xml.aspectClass() + "." + xml.method()
                        + ")를 소스에서 찾지 못했습니다. 직접 확인하세요.");
            }
            methods.forEach(m -> overwrites.addAll(candidates(m, xml.pointcut(), xml.evidence())));
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
        List<Evidenced> prefixes = loginMethodPrefixes();
        return new Draft(overwrites, loginTypes, prefixes, scopeKeyCandidates(sources, overwrites, loginPuts(prefixes)),
                FrameworkProfiler.profile(sources, java), notes, java.failedFiles());
    }

    /**
     * 서비스·컨트롤러가 로그인 정보로 직접 넣는 맵 키({@code param.put("compCd", user.getLoginCompCd())}) → 그 put 줄.
     * 공통 장치(AOP) 없이 서비스마다 세션에서 꺼내 넣는 시스템은 이것으로만 사용자 범위 키를 찾을 수 있다.
     * 로그인 정보는 세션에서 꺼낸 값·세션에서 꺼낸 타입의 getter·로그인 getter 접두어(getLogin 등)로 시작하는 메서드의 반환값이다.
     */
    private Map<String, Evidenced> loginPuts(List<Evidenced> prefixes) {
        Map<String, Evidenced> found = new LinkedHashMap<>();
        for (MethodCallExpr call : java.callsNamed("put")) {
            if (call.getArguments().size() != 2 || !(unwrap(call.getArgument(0)) instanceof StringLiteralExpr key)) continue;
            CallableDeclaration<?> method = call.findAncestor(CallableDeclaration.class).orElse(null);
            if (method == null || !isLoginValue(call.getArgument(1), method, prefixes)) continue;
            found.putIfAbsent(key.getValue(), new Evidenced(key.getValue(), java.location(call) + " " + abbreviate(call.toString())));
        }
        return found;
    }

    private boolean isLoginValue(Expression expression, CallableDeclaration<?> method, List<Evidenced> prefixes) {
        if (isSessionValue(expression, method)) return true;
        // SessionUtil.getLoginUser().getCompCd()처럼 형 변환 없이 꺼내면 타입을 모른다 — 로그인 getter 이름으로 본다.
        return unwrap(expression) instanceof MethodCallExpr call
                && prefixes.stream().anyMatch(p -> call.getNameAsString().startsWith(p.value()));
    }

    /**
     * 세션 덮어쓰기 장치가 넣는 키 중 매퍼 SQL 조건 자리(WHERE·ON·HAVING)에 쓰인 키. 로그인 정보로 데이터를 가르는 조건이라는 뜻이라
     * 사용자 범위 키 후보가 된다. 값 자리(INSERT VALUES·UPDATE SET)에만 쓰이는 키(등록자 기록)는 후보가 아니다.
     */
    private static List<Evidenced> scopeKeyCandidates(Map<String, String> sources, List<OverwriteCandidate> overwrites,
                                                      Map<String, Evidenced> loginPuts) {
        Set<String> sessionKeys = new LinkedHashSet<>();
        overwrites.forEach(c -> c.keys().forEach(k -> sessionKeys.add(k.value())));
        Set<String> overwriteKeys = Set.copyOf(sessionKeys);
        sessionKeys.addAll(loginPuts.keySet());
        if (sessionKeys.isEmpty()) return List.of();
        Map<String, Evidenced> found = new LinkedHashMap<>();
        sources.forEach((path, content) -> {
            if (!path.endsWith(".xml")) return;
            MapperXmlIndex.MapperFile mapper = MapperXmlIndex.parse(path, content);
            if (mapper == null) return;
            List<MapperXmlIndex.Dollar> uses = new ArrayList<>();
            mapper.statements().forEach(st -> {
                uses.addAll(st.hashes());
                uses.addAll(st.dollars());
            });
            mapper.fragments().forEach(f -> {
                uses.addAll(f.hashes());
                uses.addAll(f.dollars());
            });
            for (MapperXmlIndex.Dollar d : uses) {
                if (d.condition() && sessionKeys.contains(d.key())) {
                    String sql = path.substring(path.lastIndexOf('/') + 1) + ":" + d.line() + " " + d.display();
                    // 장치가 넣는 키는 장치 근거가 이미 따로 있다. 서비스가 넣는 키는 어디서 로그인 정보를 넣는지도 같이 보여준다.
                    found.putIfAbsent(d.key(), new Evidenced(d.key(), overwriteKeys.contains(d.key())
                            ? sql : sql + " ← " + loginPuts.get(d.key()).evidence()));
                }
            }
        });
        // 장치가 넣는 순서, 그다음 서비스 코드 순서대로 — 점검마다 같은 순서여야 같은 초안이다.
        List<Evidenced> result = new ArrayList<>();
        sessionKeys.forEach(k -> {
            if (found.containsKey(k)) result.add(found.get(k));
        });
        return result;
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

    /** @param adviceEvidence 어드바이스를 건 곳(어노테이션 또는 XML 태그) */
    private List<OverwriteCandidate> candidates(MethodDeclaration advice, String pointcut, String adviceEvidence) {
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
