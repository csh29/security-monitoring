package com.sjinc.cvemonitor.service.securecode;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NullLiteralExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.DoStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.LabeledStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchEntry;
import com.github.javaparser.ast.stmt.SynchronizedStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.sjinc.cvemonitor.service.securecode.DollarVerdict.Safety;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.Declaration;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.FieldDecl;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.LocalDecl;
import com.sjinc.cvemonitor.service.securecode.JavaSourceIndex.ParamDecl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * MyBatis {@code ${}}마다 그 값이 어디서 오는지 Java 소스를 따라가 판정한다. Semgrep(무료판)은 한 메서드 안만 보고 XML과 Java를
 * 잇지 못해 {@code ${}}를 전부 같은 등급으로 내는데, 실제로는 서버가 상수·로그인 정보로 채우는 것이 대부분이라
 * 사람이 매번 연계 코드를 열어 봐야 했다.
 *
 * <p>순서: 매퍼 XML의 {@code ${key}} → 그 구문을 실행하는 곳({@code sqlSession.selectList("ns.id", map)}, 감싼 메서드면 그 호출자까지)
 * → 실행 직전까지 {@code map.put("key", 값)}이 <b>모든 경로에서</b> 일어나는가 → 그 값은 상수·로그인 정보인가, 요청 값인가.
 * 맵이 파라미터로 들어왔으면 호출자로 올라가고, 컨트롤러 요청 매핑까지 가면 클라이언트 값이다.
 *
 * <p>"모든 경로에서"가 핵심이다. {@code @RequestBody Map}으로 받은 맵에는 클라이언트가 보낸 키가 이미 들어 있어서,
 * {@code if (x) map.put("k", "A")}처럼 else가 없으면 조건이 거짓일 때 클라이언트 값이 그대로 남는다.
 *
 * <p>클라이언트가 구문 id까지 정하는 공통 실행 경로(CRM의 {@code /common/selectList}: {@code selectList(param.getStatement(), paramData)})가
 * 있으면 서비스에서 세팅한 값은 그 경로로 우회된다. 그래서 그런 경로를 찾아 모든 구문의 추가 호출처로 함께 판정한다.
 * XML 안에서 정해지는 값(bind 상수, 상수 비교 if)과 세션 덮어쓰기(trace-rules.yml의 sessionOverwrites)만 그 경로로 와도 안전하다.
 *
 * <p>시스템마다 다른 프레임워크 장치(세션 값을 요청 맵에 덮어쓰는 AOP, 로그인 정보 객체 이름)는 판정 로직에 넣지 않고
 * {@link TraceRules}(securecode/trace-rules.yml)로 받는다.
 *
 * <p>Spring 없이 도는 순수 클래스다. 출처를 끝까지 못 따라가면 "판정 불가"로 남기고 안전하다고 하지 않는다.
 */
public final class MybatisDollarTracer {

    /**
     * @param verdicts     {@code ${}} 한 곳마다 판정 하나(경로·줄 순)
     * @param failedFiles  구문 분석에 실패한 파일 — 그 안의 세팅·호출을 못 봤으니 판정이 덜 정확하다
     * @param genericRoutes 클라이언트가 구문 id를 정하는 공통 실행 경로(근거 표시용)
     */
    public record Result(List<DollarVerdict> verdicts, List<String> failedFiles, List<String> genericRoutes) {
    }

    /** SqlSession의 구문 실행 메서드. */
    private static final Set<String> SQL_METHODS = Set.of(
            "selectOne", "selectList", "selectMap", "selectCursor", "select", "insert", "update", "delete");
    /** 값을 바꾸지 않고 그대로 옮기는 메서드 — 출처는 받는 쪽·인자와 같다. */
    private static final Set<String> PROPAGATING_METHODS = Set.of(
            "toString", "trim", "strip", "toUpperCase", "toLowerCase", "substring", "split", "concat", "replace",
            "replaceAll", "intern", "valueOf", "format", "join", "orElse", "ofNullable", "of", "defaultString",
            "defaultIfEmpty", "defaultIfBlank", "nvl", "toArray", "stream", "collect", "getOrDefault");
    private static final Set<String> REQUEST_GETTERS = Set.of(
            "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders", "getQueryString",
            "getRequestURI", "getRequestURL", "getCookies", "getPathInfo", "getInputStream", "getReader");
    private static final Set<String> NON_CLIENT_PARAM_TYPES = Set.of(
            "HttpServletRequest", "HttpServletResponse", "HttpSession", "Principal", "Authentication",
            "Model", "ModelMap", "BindingResult", "Locale", "RedirectAttributes");
    private static final Set<String> MAP_TYPES = Set.of(
            "Map", "HashMap", "LinkedHashMap", "TreeMap", "ConcurrentHashMap");
    /** 실제 저장소에서 갈래가 수십 개로 퍼질 수 있어 한 {@code ${}}당 따라가는 걸음 수를 제한한다. 넘기면 판정 불가. */
    private static final int MAX_STEPS = 20_000;
    private static final int MAX_DEPTH = 14;
    /** 점검에서 빼는 폴더(SemgrepRunner의 제외 목록과 같은 기준). */
    private static final Set<String> IGNORED_DIRS = Set.of(".git", "target", "build", "out", "node_modules", ".idea", ".gradle");

    private final MapperXmlIndex.MapperFile[] mappers;
    private final JavaSourceIndex java;
    private final TraceRules rules;
    private int steps;
    /** 지금 따라가는 중인 지역 변수(+키 경로). {@code sql = sql + ...}처럼 자기를 참조하는 대입에서 같은 곳을 맴돌지 않게 한다. */
    private final Set<String> visiting = new HashSet<>();

    private MybatisDollarTracer(List<MapperXmlIndex.MapperFile> mappers, JavaSourceIndex java, TraceRules rules) {
        this.mappers = mappers.toArray(MapperXmlIndex.MapperFile[]::new);
        this.java = java;
        this.rules = rules;
    }

    /** clone한 저장소를 읽어 판정한다. src/test·빌드 폴더는 Semgrep과 같은 기준으로 뺀다. */
    public static Result trace(Path projectDir, TraceRules rules) throws IOException {
        return trace(readSources(projectDir), rules);
    }

    /** 저장소의 .java·.xml을 읽는다(경로 → 내용). 추적 규칙 초안(TraceRuleDrafter)도 같은 기준으로 읽는다. */
    static Map<String, String> readSources(Path projectDir) throws IOException {
        Map<String, String> sources = new TreeMap<>();
        try (Stream<Path> files = Files.walk(projectDir)) {
            for (Path file : (Iterable<Path>) files::iterator) {
                String relative = projectDir.relativize(file).toString().replace('\\', '/');
                if (!Files.isRegularFile(file) || isIgnored(relative)) continue;
                if (relative.endsWith(".java") || relative.endsWith(".xml")) {
                    sources.put(relative, SecureCodeSnippetBuilder.decode(Files.readAllBytes(file)));
                }
            }
        }
        return sources;
    }

    private static boolean isIgnored(String relative) {
        if (relative.startsWith("src/test/") || relative.contains("/src/test/")) return true;
        for (String part : relative.split("/")) {
            if (IGNORED_DIRS.contains(part)) return true;
        }
        return false;
    }

    /** @param sources 저장소 루트 기준 경로 → 내용(.java, .xml) */
    static Result trace(Map<String, String> sources, TraceRules rules) {
        List<MapperXmlIndex.MapperFile> mappers = new ArrayList<>();
        Map<String, String> javaSources = new LinkedHashMap<>();
        sources.forEach((path, content) -> {
            if (path.endsWith(".xml")) {
                MapperXmlIndex.MapperFile mapper = MapperXmlIndex.parse(path, content);
                if (mapper != null) mappers.add(mapper);
            } else if (path.endsWith(".java")) {
                javaSources.put(path, content);
            }
        });
        return new MybatisDollarTracer(mappers, JavaSourceIndex.build(javaSources), rules).run();
    }

    // ================================================================ 전체 흐름

    /** 구문 하나를 실행하는 곳. frame은 감싼 메서드를 거쳐 왔으면 그 호출자에 묶인 상태다. */
    private record Site(MethodCallExpr sink, Frame frame, List<String> evidence) {
    }

    private Result run() {
        Map<String, MapperXmlIndex.Statement> statements = new LinkedHashMap<>();
        Map<String, MapperXmlIndex.Fragment> fragments = new HashMap<>();
        for (MapperXmlIndex.MapperFile mapper : mappers) {
            mapper.statements().forEach(s -> statements.put(s.fullId(), s));
            mapper.fragments().forEach(f -> fragments.put(f.fullId(), f));
        }

        Map<String, List<Site>> sitesByStatement = new HashMap<>();
        List<Site> genericSites = new ArrayList<>();
        for (String name : SQL_METHODS) {
            for (MethodCallExpr call : java.callsNamed(name)) {
                if (!isSqlSink(call)) continue;
                CallableDeclaration<?> method = call.findAncestor(CallableDeclaration.class).orElse(null);
                if (method == null) continue;
                steps = 0;
                for (StatementRef ref : resolveStatement(call.getArgument(0), Frame.root(method), 0)) {
                    Site site = new Site(call, ref.frame(), ref.evidence());
                    if (ref.safety() == Safety.CLIENT) {
                        genericSites.add(site);
                    } else if (ref.id() != null) {
                        String id = qualify(ref.id(), statements.keySet());
                        sitesByStatement.computeIfAbsent(id, k -> new ArrayList<>()).add(site);
                    }
                }
            }
        }

        List<String> genericRoutes = genericSites.stream()
                .map(site -> String.join(" → ", site.evidence()))
                .distinct().toList();

        // 조각은 그 조각을 include한 구문마다 판정해 가장 나쁜 것을 쓴다.
        Map<String, List<String>> includers = new HashMap<>();
        statements.values().forEach(s -> collectIncludes(s.fullId(), s.includes(), fragments, includers, new HashSet<>()));

        List<DollarVerdict> verdicts = new ArrayList<>();
        for (MapperXmlIndex.MapperFile mapper : mappers) {
            for (MapperXmlIndex.Statement s : mapper.statements()) {
                for (MapperXmlIndex.Dollar d : s.dollars()) {
                    verdicts.add(judge(d, List.of(s.fullId()), sitesByStatement, genericSites));
                }
            }
            for (MapperXmlIndex.Fragment f : mapper.fragments()) {
                for (MapperXmlIndex.Dollar d : f.dollars()) {
                    verdicts.add(judge(d, includers.getOrDefault(f.fullId(), List.of()), sitesByStatement, genericSites));
                }
            }
        }
        verdicts.sort((a, b) -> a.path().equals(b.path()) ? Integer.compare(a.line(), b.line()) : a.path().compareTo(b.path()));
        return new Result(verdicts, java.failedFiles(), genericRoutes);
    }

    private static void collectIncludes(String statementId, Set<String> includes, Map<String, MapperXmlIndex.Fragment> fragments,
                                        Map<String, List<String>> includers, Set<String> seen) {
        for (String include : includes) {
            if (!seen.add(include)) continue;
            includers.computeIfAbsent(include, k -> new ArrayList<>()).add(statementId);
            MapperXmlIndex.Fragment fragment = fragments.get(include);
            if (fragment != null) collectIncludes(statementId, fragment.includes(), fragments, includers, seen);
        }
    }

    /** 구문 id에 namespace가 없으면(MyBatis는 유일하면 짧은 id도 받는다) 유일하게 맞는 전체 id로 바꾼다. */
    private static String qualify(String id, Set<String> known) {
        if (known.contains(id)) return id;
        String suffix = "." + id;
        List<String> matches = known.stream().filter(k -> k.endsWith(suffix)).toList();
        return matches.size() == 1 ? matches.get(0) : id;
    }

    private DollarVerdict judge(MapperXmlIndex.Dollar d, List<String> statementIds,
                                Map<String, List<Site>> sitesByStatement, List<Site> genericSites) {
        String xmlStep = d.path().substring(d.path().lastIndexOf('/') + 1) + ":" + d.line() + " ${" + d.expr() + "}";
        if (d.xmlFixed() != null) {
            return verdict(d, String.join(", ", statementIds), V.of(Safety.XML_FIXED, d.xmlFixed()), xmlStep);
        }
        if (statementIds.isEmpty()) {
            return verdict(d, "", V.of(Safety.UNKNOWN, "이 sql 조각을 include하는 구문이 없음"), xmlStep);
        }
        V worst = null;
        String worstStatement = statementIds.get(0);
        for (String statementId : statementIds) {
            V v = judgeStatement(d, statementId, sitesByStatement.getOrDefault(statementId, List.of()), genericSites);
            if (worst == null || v.safety().worseThan(worst.safety())) {
                worst = v;
                worstStatement = statementId;
            }
        }
        return verdict(d, worstStatement, worst, xmlStep + " (" + worstStatement + ")");
    }

    private V judgeStatement(MapperXmlIndex.Dollar d, String statementId, List<Site> direct, List<Site> generic) {
        Set<String> keys = d.bindFrom().isEmpty() ? Set.of(d.key()) : d.bindFrom();
        String bindNote = d.bindFrom().isEmpty() ? null : "<bind name=\"" + d.key() + "\">가 " + keys + " 로 만든 값";
        V directV = null;
        for (Site site : direct) {
            for (String key : keys) {
                directV = V.worst(directV, keyAtSite(site, key, bindNote));
            }
        }
        V genericV = null;
        for (Site site : generic) {
            for (String key : keys) {
                genericV = V.worst(genericV, keyAtSite(site, key, bindNote));
            }
        }
        if (directV == null && genericV == null) {
            return V.of(Safety.UNKNOWN, "이 구문(" + statementId + ")을 실행하는 Java 코드를 찾지 못함");
        }
        if (directV == null) {
            // 직접 부르는 곳이 없고 공통 실행 경로로만 실행된다 — 그 경로의 판정이 곧 결론이다.
            return genericV.safety() == Safety.CLIENT
                    ? genericV.append("직접 호출처 없이 공통 실행 경로로만 실행됨") : genericV;
        }
        if (directV.safety() == Safety.CLIENT || genericV == null || genericV.safety() != Safety.CLIENT) {
            return V.worst(directV, genericV);
        }
        // 서비스 경로는 클라이언트 값이 아니지만, 공통 실행 경로로 직접 부르면 클라이언트 값이 들어간다.
        List<String> evidence = new ArrayList<>(directV.evidence());
        evidence.add("그러나 공통 실행 경로로 이 구문을 직접 부르면: " + String.join(" → ", genericV.evidence()));
        return new V(Safety.BYPASSABLE, evidence);
    }

    /** 이 실행 경로에서 key의 출처. 이 경로로는 key에 값이 닿을 수 없으면 null. */
    private V keyAtSite(Site site, String key, String bindNote) {
        steps = 0;
        MethodCallExpr sink = site.sink();
        V v;
        if (sink.getArguments().size() < 2) {
            v = V.of(Safety.SERVER_SET, "파라미터 없이 실행");
        } else if (isCollectionArgument(sink.getArgument(1), site.frame())) {
            // MyBatis는 List·배열 파라미터를 list/collection/array 키로 감싼다 — ${key}는 원소에 닿지 않는다
            // (CRM Syc020Service.saveMenu의 insert(statement, menuData)를 클라이언트 경로로 잘못 잡았었다).
            // 이 실행 경로로는 이 키에 값을 넣을 수 없으니 판정에서 뺀다(null).
            return null;
        } else {
            v = keyOf(sink.getArgument(1), List.of(key), sink, site.frame(), 0);
        }
        v = v.append(java.location(sink) + " " + abbreviate(sink.toString()));
        return bindNote == null ? v : v.append(bindNote);
    }

    private DollarVerdict verdict(MapperXmlIndex.Dollar d, String statement, V v, String xmlStep) {
        List<String> evidence = new ArrayList<>(v.evidence());
        evidence.add(xmlStep);
        return new DollarVerdict(d.path(), d.line(), statement, d.expr(), d.key(), v.safety(), evidence);
    }

    // ================================================================ 판정 값

    /** 판정과 근거(출처 → … → 현재 위치 순). */
    private record V(Safety safety, List<String> evidence) {
        static V of(Safety safety, String step) {
            return new V(safety, List.of(step));
        }

        V append(String step) {
            List<String> next = new ArrayList<>(evidence);
            next.add(step);
            return new V(safety, next);
        }

        /** 더 위험한 쪽. 같으면 먼저 온 쪽(근거가 짧은 경우가 많다). */
        static V worst(V a, V b) {
            if (a == null) return b;
            if (b == null) return a;
            return b.safety().worseThan(a.safety()) ? b : a;
        }
    }

    /**
     * 메서드 하나의 실행 문맥. 호출자에서 내려왔으면 파라미터 이름 → 호출 인자가 묶여 있고(bindings),
     * 인스턴스 메서드면 받는 쪽 식(receiver — {@code param.getStatement()}의 param)도 들고 있다.
     */
    private static final class Frame {
        final CallableDeclaration<?> method;
        final Map<String, Binding> bindings;
        final Binding receiver;

        private Frame(CallableDeclaration<?> method, Map<String, Binding> bindings, Binding receiver) {
            this.method = method;
            this.bindings = bindings;
            this.receiver = receiver;
        }

        static Frame root(CallableDeclaration<?> method) {
            return new Frame(method, Map.of(), null);
        }

        /** callee를 call로 부른 문맥. callerFrame은 call이 있는 메서드의 문맥. */
        static Frame call(CallableDeclaration<?> callee, MethodCallExpr call, Frame callerFrame) {
            Map<String, Binding> bindings = new HashMap<>();
            List<Parameter> params = callee.getParameters();
            for (int i = 0; i < params.size() && i < call.getArguments().size(); i++) {
                bindings.put(params.get(i).getNameAsString(), new Binding(call.getArgument(i), callerFrame, call));
            }
            Binding receiver = call.getScope().filter(s -> !(s instanceof ThisExpr))
                    .map(s -> new Binding(s, callerFrame, call)).orElse(null);
            return new Frame(callee, bindings, receiver);
        }
    }

    private record Binding(Expression arg, Frame caller, MethodCallExpr call) {
    }

    // ================================================================ 구문 id 찾기

    /** 구문 실행의 구문 id 출처. id가 있으면 그 구문, safety가 CLIENT면 클라이언트가 구문을 고르는 공통 실행 경로. */
    private record StatementRef(String id, Safety safety, Frame frame, List<String> evidence) {
    }

    private boolean isSqlSink(MethodCallExpr call) {
        if (call.getArguments().isEmpty() || call.getScope().isEmpty() || !java.resolve(call).isEmpty()) return false;
        Expression scope = call.getScope().get();
        String type = java.typeNameOf(scope);
        if (type != null) return type.contains("SqlSession");
        String text = scope.toString().toLowerCase();
        return text.contains("sql") || text.contains("session");
    }

    private List<StatementRef> resolveStatement(Expression expression, Frame frame, int depth) {
        Expression e = unwrap(expression);
        String constant = constantString(e);
        if (constant != null) {
            return List.of(new StatementRef(constant, Safety.SERVER_SET, frame, List.of()));
        }
        if (depth < MAX_DEPTH && e instanceof NameExpr name) {
            Optional<Declaration> declaration = java.declarationOf(name);
            if (declaration.isPresent() && declaration.get() instanceof ParamDecl param
                    && param.callable() == frame.method && !java.isHandler(param.callable())
                    && param.callable() instanceof MethodDeclaration method) {
                // 구문 id를 파라미터로 받는 감싼 메서드(CommonService.selectList(statement, param)) — 호출자마다 따로 본다.
                List<StatementRef> refs = new ArrayList<>();
                for (MethodCallExpr call : java.callersOf(method)) {
                    CallableDeclaration<?> caller = call.findAncestor(CallableDeclaration.class).orElse(null);
                    if (caller == null || param.index() >= call.getArguments().size()) continue;
                    for (StatementRef ref : resolveStatement(call.getArgument(param.index()), Frame.root(caller), depth + 1)) {
                        List<String> evidence = new ArrayList<>(ref.evidence());
                        evidence.add(java.location(call) + " " + abbreviate(call.toString()));
                        refs.add(new StatementRef(ref.id(), ref.safety(), Frame.call(method, call, ref.frame()), evidence));
                    }
                }
                return refs;
            }
            if (declaration.isPresent() && declaration.get() instanceof LocalDecl local
                    && local.variable().getInitializer().isPresent()) {
                return resolveStatement(local.variable().getInitializer().get(), frame, depth + 1);
            }
        }
        V v = valueOf(e, frame, depth);
        if (v.safety() == Safety.CLIENT) {
            return List.of(new StatementRef(null, Safety.CLIENT, frame, v.evidence()));
        }
        return List.of();
    }

    /** 상수 문자열이면 그 값(리터럴, 리터럴끼리 +, static final 문자열 필드). 아니면 null. */
    private String constantString(Expression expression) {
        Expression e = unwrap(expression);
        if (e instanceof StringLiteralExpr literal) return literal.getValue();
        if (e instanceof BinaryExpr binary && binary.getOperator() == BinaryExpr.Operator.PLUS) {
            String left = constantString(binary.getLeft());
            String right = constantString(binary.getRight());
            return left != null && right != null ? left + right : null;
        }
        if (e instanceof NameExpr name) {
            Optional<Declaration> declaration = java.declarationOf(name);
            if (declaration.isPresent() && declaration.get() instanceof FieldDecl field
                    && field.field().isFinal() && field.variable().getInitializer().isPresent()) {
                return constantString(field.variable().getInitializer().get());
            }
        }
        return null;
    }

    // ================================================================ 맵의 키 값 따라가기

    /**
     * 맵 식의 키 값이 at 시점에 어디서 왔는가. path는 꺼내는 키 경로다 — {@code param.get("paramData")}의 "loginBrndzCd"면
     * param에 대해 [paramData, loginBrndzCd].
     */
    private V keyOf(Expression mapExpression, List<String> path, Node at, Frame frame, int depth) {
        if (++steps > MAX_STEPS || depth > MAX_DEPTH) {
            return V.of(Safety.UNKNOWN, "추적 범위 초과(" + java.location(at) + ")");
        }
        Expression e = unwrap(mapExpression);
        if (e instanceof NullLiteralExpr) {
            return V.of(Safety.SERVER_SET, "파라미터 없이 실행");
        }
        if (e instanceof ObjectCreationExpr creation && isMapType(creation.getType().getNameAsString())) {
            if (creation.getArguments().isEmpty()) {
                return V.of(Safety.SERVER_SET, java.location(creation) + " 서버가 새로 만든 맵 — " + path.get(0) + " 키 없음");
            }
            return keyOf(creation.getArgument(0), path, at, frame, depth + 1)
                    .append(java.location(creation) + " 맵 복사 " + abbreviate(creation.toString()));
        }
        if (e instanceof MethodCallExpr call && isMapGet(call)) {
            List<String> longer = new ArrayList<>();
            longer.add(((StringLiteralExpr) unwrap(call.getArgument(0))).getValue());
            longer.addAll(path);
            Expression scope = call.getScope().orElse(new ThisExpr());
            return keyOf(scope, longer, at, frame, depth + 1);
        }
        if (e instanceof ThisExpr) {
            if (frame.receiver != null) {
                Binding r = frame.receiver;
                return keyOf(r.arg(), path, r.call(), r.caller(), depth + 1);
            }
            return V.of(Safety.UNKNOWN, java.location(at) + " this 맵 — 받는 쪽을 모름");
        }
        if (e instanceof NameExpr name) {
            return keyOfName(name, path, at, frame, depth);
        }
        return V.of(Safety.UNKNOWN, java.location(e) + " 맵 출처를 모름: " + abbreviate(e.toString()));
    }

    private V keyOfName(NameExpr name, List<String> path, Node at, Frame frame, int depth) {
        String mapName = name.getNameAsString();
        String key = path.get(0);
        Optional<Declaration> declaration = java.declarationOf(name);

        // 1) 실행 직전까지 같은 메서드 안의 put("key", 값)
        List<V> putValues = new ArrayList<>();
        boolean covered = false;
        if (at.findAncestor(CallableDeclaration.class).orElse(null) == frame.method) {
            for (MethodCallExpr put : frame.method.findAll(MethodCallExpr.class)) {
                if (!before(put, at) || !isPutOf(put, mapName, key)) continue;
                V value = path.size() == 1
                        ? valueOf(put.getArgument(1), frame, depth + 1)
                        : keyOf(put.getArgument(1), path.subList(1, path.size()), put, frame, depth + 1);
                boolean must = mustExecuteBefore(put, at, mapName, key);
                covered |= must;
                putValues.add(value.append(java.location(put) + " " + abbreviate(put.toString())
                        + (must ? "" : " (조건부)")));
            }
            // 맵을 넘겨받아 키를 채우는 우리 메서드(fillDefaults(param)) — 그 메서드가 모든 경로에서 채우면 덮어쓴 것으로 본다.
            for (MethodCallExpr call : frame.method.findAll(MethodCallExpr.class)) {
                if (!before(call, at) || path.size() != 1) continue;
                for (int i = 0; i < call.getArguments().size(); i++) {
                    if (!(unwrap(call.getArgument(i)) instanceof NameExpr arg) || !arg.getNameAsString().equals(mapName)) continue;
                    for (MethodDeclaration callee : java.resolve(call)) {
                        String paramName = callee.getParameter(i).getNameAsString();
                        BlockStmt body = callee.getBody().orElse(null);
                        if (body == null) continue;
                        Frame calleeFrame = Frame.call(callee, call, frame);
                        for (MethodCallExpr put : body.findAll(MethodCallExpr.class)) {
                            if (!isPutOf(put, paramName, key)) continue;
                            putValues.add(valueOf(put.getArgument(1), calleeFrame, depth + 1)
                                    .append(java.location(put) + " " + abbreviate(put.toString())));
                        }
                        // 호출된 메서드의 return은 put 없이 호출자로 돌아오는 것이라 "덮어씀"으로 치지 않는다(abruptCovers=false).
                        if (alwaysPuts(body, paramName, key, false) && mustExecuteBefore(call, at, mapName, key)) covered = true;
                    }
                }
            }
        }
        V result = null;
        for (V v : putValues) result = V.worst(result, v);
        if (covered && result != null) return result;

        // 2) 덮어쓰지 않았으면(또는 조건부로만 덮어썼으면) 맵이 원래 들고 온 값
        V origin = originKey(name, declaration, path, at, frame, depth);
        if (!putValues.isEmpty()) {
            origin = origin.append("조건부로만 세팅 — 조건이 거짓이면 원래 값(" + key + ")이 그대로 남음");
        }
        return V.worst(result, origin);
    }

    private V originKey(NameExpr name, Optional<Declaration> declaration, List<String> path, Node at, Frame frame, int depth) {
        String mapName = name.getNameAsString();
        Binding binding = frame.bindings.get(mapName);
        if (binding != null && declaration.isPresent() && declaration.get() instanceof ParamDecl p && p.callable() == frame.method) {
            return keyOf(binding.arg(), path, binding.call(), binding.caller(), depth + 1)
                    .append(java.location(binding.call()) + " " + abbreviate(binding.call().toString()));
        }
        if (declaration.isEmpty()) {
            return V.of(Safety.UNKNOWN, java.location(name) + " " + mapName + " 선언을 찾지 못함");
        }
        Declaration decl = declaration.get();
        if (decl instanceof ParamDecl param) {
            if (java.isHandler(param.callable())) {
                return clientMap(param, path);
            }
            if (!(param.callable() instanceof MethodDeclaration method)) {
                return V.of(Safety.UNKNOWN, java.location(param.parameter()) + " 생성자 파라미터");
            }
            List<MethodCallExpr> callers = java.callersOf(method);
            if (callers.isEmpty()) {
                return V.of(Safety.UNKNOWN, java.location(method) + " " + method.getNameAsString() + "() 호출처를 찾지 못함");
            }
            V worst = null;
            for (MethodCallExpr call : callers) {
                CallableDeclaration<?> caller = call.findAncestor(CallableDeclaration.class).orElse(null);
                if (caller == null || param.index() >= call.getArguments().size()) continue;
                V v = keyOf(call.getArgument(param.index()), path, call, Frame.root(caller), depth + 1)
                        .append(java.location(call) + " " + abbreviate(call.toString()));
                worst = V.worst(worst, v);
                if (worst.safety() == Safety.CLIENT) break;
            }
            return worst != null ? worst : V.of(Safety.UNKNOWN, method.getNameAsString() + "() 호출처를 찾지 못함");
        }
        if (decl instanceof LocalDecl local) {
            if (local.forEach() != null) {
                // for (Map row : list)의 row — 원소의 키는 리스트를 거쳐 온다(리스트 자체는 키 경로에 넣지 않는다).
                // 세션 덮어쓰기 규칙도 container가 맵 목록이면 각 행에 덮어쓴다고 보고 같은 경로로 판정한다(sjinc @AddUserInfo가 그렇다).
                return keyOf(local.forEach().getIterable(), path, local.forEach(), frame, depth + 1);
            }
            List<Expression> sources = new ArrayList<>();
            local.variable().getInitializer().ifPresent(sources::add);
            for (AssignExpr assign : local.callable().findAll(AssignExpr.class)) {
                if (assign.getTarget() instanceof NameExpr target && target.getNameAsString().equals(mapName) && before(assign, at)) {
                    sources.add(assign.getValue());
                }
            }
            if (sources.isEmpty()) {
                return V.of(Safety.UNKNOWN, java.location(local.variable()) + " " + mapName + " 값이 정해지는 곳을 모름");
            }
            String mark = System.identityHashCode(local.variable()) + ":" + path;
            if (!visiting.add(mark)) {
                return V.of(Safety.SERVER_SET, java.location(name) + " " + mapName + " (자기 참조)");
            }
            try {
                V worst = null;
                for (Expression source : sources) {
                    worst = V.worst(worst, keyOf(source, path, source, frame, depth + 1));
                }
                return worst;
            } finally {
                visiting.remove(mark);
            }
        }
        return V.of(Safety.UNKNOWN, java.location(name) + " 필드·람다 변수 " + mapName + " — 값이 정해지는 곳을 모름");
    }

    /** 컨트롤러가 요청으로 받은 맵. 세션 덮어쓰기(trace-rules.yml) 대상 키만 안전하다. */
    private V clientMap(ParamDecl param, List<String> path) {
        CallableDeclaration<?> handler = param.callable();
        String label = java.location(handler) + " " + java.handlerLabel(handler) + " (" + param.parameter() + ")";
        if (NON_CLIENT_PARAM_TYPES.contains(JavaSourceIndex.simpleName(param.parameter().getType()))) {
            return V.of(Safety.UNKNOWN, label + " — 요청 맵이 아님");
        }
        String key = path.get(path.size() - 1);
        for (TraceRules.SessionOverwrite rule : rules.sessionOverwrites()) {
            if (overwrites(rule, handler, path)) {
                return V.of(Safety.SESSION_OVERWRITE, label + " " + rule.name() + "가 " + key + "를 세션 값으로 덮어씀");
            }
        }
        return V.of(Safety.CLIENT, label + " — 클라이언트가 보낸 " + String.join(".", path));
    }

    /** 이 요청 매핑에서 rule이 path(요청 맵 기준 키 경로)를 세션 값으로 덮어쓰는가. */
    private static boolean overwrites(TraceRules.SessionOverwrite rule, CallableDeclaration<?> handler, List<String> path) {
        if (!JavaSourceIndex.hasAnnotation(handler, rule.annotation())) return false;
        if (rule.requiredFirstParam() != null && (handler.getParameters().isEmpty()
                || !rule.requiredFirstParam().equals(JavaSourceIndex.simpleName(handler.getParameter(0).getType())))) {
            return false;
        }
        List<String> expected = rule.container() == null ? List.of() : List.of(rule.container());
        return path.size() == expected.size() + 1
                && path.subList(0, expected.size()).equals(expected)
                && rule.keys().contains(path.get(path.size() - 1));
    }

    // ================================================================ 값 따라가기

    private V valueOf(Expression expression, Frame frame, int depth) {
        if (++steps > MAX_STEPS || depth > MAX_DEPTH) {
            return V.of(Safety.UNKNOWN, "추적 범위 초과(" + java.location(expression) + ")");
        }
        Expression e = unwrap(expression);
        if (e instanceof LiteralExpr) {
            return V.of(Safety.SERVER_SET, java.location(e) + " 상수 " + abbreviate(e.toString()));
        }
        if (e instanceof ConditionalExpr conditional) {
            return V.worst(valueOf(conditional.getThenExpr(), frame, depth + 1), valueOf(conditional.getElseExpr(), frame, depth + 1));
        }
        if (e instanceof BinaryExpr binary) {
            if (binary.getOperator() != BinaryExpr.Operator.PLUS) {
                return V.of(Safety.SERVER_SET, java.location(e) + " 비교·연산 결과");
            }
            return V.worst(valueOf(binary.getLeft(), frame, depth + 1), valueOf(binary.getRight(), frame, depth + 1));
        }
        if (e instanceof UnaryExpr unary) {
            return valueOf(unary.getExpression(), frame, depth + 1);
        }
        if (e instanceof AssignExpr assign) {
            return valueOf(assign.getValue(), frame, depth + 1);
        }
        if (e instanceof NameExpr name) {
            return valueOfName(name, frame, depth);
        }
        if (e instanceof FieldAccessExpr access) {
            if (isConstantName(access.getNameAsString())) {
                return V.of(Safety.SERVER_SET, java.location(e) + " 상수 " + access);
            }
            return V.of(Safety.UNKNOWN, java.location(e) + " 필드 " + access + " — 값이 정해지는 곳을 모름");
        }
        if (e.isArrayAccessExpr()) {
            return valueOf(e.asArrayAccessExpr().getName(), frame, depth + 1);
        }
        if (e instanceof ObjectCreationExpr creation && Set.of("String", "StringBuilder", "StringBuffer")
                .contains(creation.getType().getNameAsString())) {
            return worstOf(creation.getArguments(), frame, depth, V.of(Safety.SERVER_SET, java.location(e) + " 빈 문자열"));
        }
        if (e instanceof MethodCallExpr call) {
            return valueOfCall(call, frame, depth);
        }
        return V.of(Safety.UNKNOWN, java.location(e) + " 해석하지 못한 식: " + abbreviate(e.toString()));
    }

    private V valueOfName(NameExpr name, Frame frame, int depth) {
        String id = name.getNameAsString();
        Optional<Declaration> declaration = java.declarationOf(name);
        Binding binding = frame.bindings.get(id);
        if (binding != null && declaration.isPresent() && declaration.get() instanceof ParamDecl p && p.callable() == frame.method) {
            return valueOf(binding.arg(), binding.caller(), depth + 1)
                    .append(java.location(binding.call()) + " " + abbreviate(binding.call().toString()));
        }
        if (declaration.isEmpty()) {
            return isConstantName(id) ? V.of(Safety.SERVER_SET, java.location(name) + " 상수 " + id)
                    : V.of(Safety.UNKNOWN, java.location(name) + " " + id + " 선언을 찾지 못함");
        }
        Declaration decl = declaration.get();
        if (decl instanceof ParamDecl param) {
            if (java.isHandler(param.callable())) {
                String type = JavaSourceIndex.simpleName(param.parameter().getType());
                if (NON_CLIENT_PARAM_TYPES.contains(type)) {
                    return V.of(Safety.UNKNOWN, java.location(param.parameter()) + " " + param.parameter());
                }
                return V.of(Safety.CLIENT, java.location(param.callable()) + " " + java.handlerLabel(param.callable())
                        + " (" + param.parameter() + ") — 클라이언트가 보낸 값");
            }
            if (!(param.callable() instanceof MethodDeclaration method)) {
                return V.of(Safety.UNKNOWN, java.location(param.parameter()) + " 생성자 파라미터 " + id);
            }
            List<MethodCallExpr> callers = java.callersOf(method);
            if (callers.isEmpty()) {
                return V.of(Safety.UNKNOWN, java.location(method) + " " + method.getNameAsString() + "() 호출처를 찾지 못함");
            }
            V worst = null;
            for (MethodCallExpr call : callers) {
                CallableDeclaration<?> caller = call.findAncestor(CallableDeclaration.class).orElse(null);
                if (caller == null || param.index() >= call.getArguments().size()) continue;
                worst = V.worst(worst, valueOf(call.getArgument(param.index()), Frame.root(caller), depth + 1)
                        .append(java.location(call) + " " + abbreviate(call.toString())));
                if (worst.safety() == Safety.CLIENT) break;
            }
            return worst != null ? worst : V.of(Safety.UNKNOWN, method.getNameAsString() + "() 호출처를 찾지 못함");
        }
        if (decl instanceof LocalDecl local) {
            if (local.forEach() != null) {
                return valueOf(local.forEach().getIterable(), frame, depth + 1);
            }
            // 지역 변수는 선언 값과 모든 대입 값 중 가장 나쁜 것 — switch·if로 나눠 대입해도 모두 상수면 상수다(getTableNm).
            List<Expression> sources = new ArrayList<>();
            local.variable().getInitializer().ifPresent(sources::add);
            for (AssignExpr assign : local.callable().findAll(AssignExpr.class)) {
                if (assign.getTarget() instanceof NameExpr target && target.getNameAsString().equals(id)) sources.add(assign);
            }
            if (sources.isEmpty()) {
                return V.of(Safety.UNKNOWN, java.location(local.variable()) + " " + id + " 값이 정해지는 곳을 모름");
            }
            String mark = System.identityHashCode(local.variable()) + ":value";
            if (!visiting.add(mark)) {
                // 이미 따라가는 중 — 나머지 대입들이 판정을 정한다(이 갈래는 판정에 보태지 않는다).
                return V.of(Safety.SERVER_SET, java.location(name) + " " + id + " (자기 참조)");
            }
            try {
                return worstOf(sources, frame, depth, null);
            } finally {
                visiting.remove(mark);
            }
        }
        if (decl instanceof FieldDecl field) {
            if (JavaSourceIndex.hasAnnotation(field.field(), "Value")) {
                return V.of(Safety.SERVER_SET, java.location(field.variable()) + " 설정값(@Value) " + id);
            }
            if (field.field().isFinal() && field.variable().getInitializer().isPresent()) {
                return valueOf(field.variable().getInitializer().get(), frame, depth + 1);
            }
            if (isConstantName(id)) {
                return V.of(Safety.SERVER_SET, java.location(field.variable()) + " 상수 " + id);
            }
            return V.of(Safety.UNKNOWN, java.location(field.variable()) + " 필드 " + id + " — 값이 정해지는 곳을 모름");
        }
        return V.of(Safety.UNKNOWN, java.location(name) + " 람다·catch 변수 " + id);
    }

    private V valueOfCall(MethodCallExpr call, Frame frame, int depth) {
        String name = call.getNameAsString();
        Optional<Expression> scope = call.getScope();
        String location = java.location(call);

        if (isMapGet(call)) {
            Expression map = scope.orElse(new ThisExpr());
            String key = ((StringLiteralExpr) unwrap(call.getArgument(0))).getValue();
            V v = keyOf(map, List.of(key), call, frame, depth + 1);
            if (name.equals("getOrDefault") && call.getArguments().size() > 1) {
                v = V.worst(v, valueOf(call.getArgument(1), frame, depth + 1));
            }
            return v;
        }
        // 로그인 정보: 세션 속성(Servlet 표준)과 trace-rules.yml의 이름 규칙(loginUserVo.getLoginBrndzCd() 등)
        String scopeType = scope.map(java::typeNameOf).orElse(null);
        if (isLoginInfo(name, scopeType)
                || (name.equals("getAttribute") && scope.map(s -> s.toString().contains("getSession")).orElse(false))) {
            return V.of(Safety.SERVER_SET, location + " 로그인 정보 " + abbreviate(call.toString()));
        }
        if (REQUEST_GETTERS.contains(name) && "HttpServletRequest".equals(scopeType)) {
            return V.of(Safety.CLIENT, location + " 요청 값 " + abbreviate(call.toString()));
        }
        List<MethodDeclaration> callees = java.resolve(call);
        if (!callees.isEmpty()) {
            // 우리 메서드면 반환문들을 본다(getTableNm처럼 모든 분기가 상수를 반환하면 상수).
            V worst = null;
            for (MethodDeclaration callee : callees) {
                Frame calleeFrame = Frame.call(callee, call, frame);
                List<ReturnStmt> returns = callee.findAll(ReturnStmt.class).stream()
                        .filter(r -> r.findAncestor(LambdaExpr.class).isEmpty() && r.getExpression().isPresent())
                        .toList();
                for (ReturnStmt ret : returns) {
                    worst = V.worst(worst, valueOf(ret.getExpression().get(), calleeFrame, depth + 1));
                }
            }
            return worst == null ? V.of(Safety.UNKNOWN, location + " " + name + "() 반환값을 모름")
                    : worst.append(location + " " + abbreviate(call.toString()) + " 반환값");
        }
        if (PROPAGATING_METHODS.contains(name)) {
            List<Expression> parts = new ArrayList<>(call.getArguments());
            scope.filter(s -> !(s instanceof NameExpr n && isClassName(n))).ifPresent(parts::add);
            return worstOf(parts, frame, depth, V.of(Safety.SERVER_SET, location + " " + name + "()"));
        }
        return V.of(Safety.UNKNOWN, location + " 외부 메서드 " + abbreviate(call.toString()));
    }

    private V worstOf(List<? extends Expression> expressions, Frame frame, int depth, V whenEmpty) {
        V worst = null;
        for (Expression expression : expressions) {
            worst = V.worst(worst, valueOf(expression, frame, depth + 1));
            if (worst.safety() == Safety.CLIENT) break;
        }
        return worst != null ? worst : whenEmpty;
    }

    // ================================================================ 실행 경로

    /**
     * put이 at보다 먼저, 그리고 at에 도달하는 모든 경로에서 실행되는가. put에서 위로 올라가며 at과 공통 조상에 닿기 전에
     * 조건(if 한쪽, 반복, catch, 람다, 삼항, &&·||)이 끼면 조건부다. 단 if/else 양쪽이 모두 같은 키를 넣으면(또는 반대쪽이
     * return·throw로 끝나 at에 못 오면) 그 if는 조건이 아니다.
     */
    private static boolean mustExecuteBefore(Node put, Node at, String mapName, String key) {
        Set<Node> atAncestors = Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (Node n = at; n != null; n = n.getParentNode().orElse(null)) atAncestors.add(n);
        Node node = put;
        while (node.getParentNode().isPresent()) {
            Node parent = node.getParentNode().get();
            if (atAncestors.contains(parent)) return true;
            if (parent instanceof IfStmt ifStmt && node != ifStmt.getCondition()) {
                Statement other = node == ifStmt.getThenStmt() ? ifStmt.getElseStmt().orElse(null) : ifStmt.getThenStmt();
                if (other == null || !alwaysPuts(other, mapName, key, true)) return false;
            }
            if (parent instanceof ForStmt || parent instanceof ForEachStmt || parent instanceof WhileStmt
                    || parent instanceof SwitchEntry || parent instanceof CatchClause || parent instanceof LambdaExpr
                    || parent instanceof ConditionalExpr) {
                return false;
            }
            if (parent instanceof BinaryExpr binary && node == binary.getRight()
                    && (binary.getOperator() == BinaryExpr.Operator.AND || binary.getOperator() == BinaryExpr.Operator.OR)) {
                return false;
            }
            if (parent instanceof CallableDeclaration) return false;
            node = parent;
        }
        return false;
    }

    /** 문장이 끝날 때까지 반드시 map.put(key, …)을 하거나, at에 도달하지 못하고 빠져나가는가(return·throw). */
    /** @param abruptCovers return·throw로 끝나면 덮어쓴 것으로 칠지 — if 반대쪽이면 at에 못 오므로 true, 호출된 메서드 본문이면 false */
    private static boolean alwaysPuts(Statement statement, String mapName, String key, boolean abruptCovers) {
        if (statement instanceof BlockStmt block) {
            for (Statement s : block.getStatements()) {
                if (alwaysPuts(s, mapName, key, abruptCovers)) return true;
                // 호출된 메서드에서 put보다 앞에 빠져나갈 수 있는 return이 있으면 put이 안 될 수 있다.
                if (!abruptCovers && (s.isReturnStmt() || s.findFirst(ReturnStmt.class,
                        r -> r.findAncestor(LambdaExpr.class).isEmpty()).isPresent())) return false;
            }
            return false;
        }
        if (statement instanceof ExpressionStmt expressionStmt) {
            return expressionStmt.getExpression() instanceof MethodCallExpr call && isPutOf(call, mapName, key);
        }
        if (statement instanceof ReturnStmt || statement instanceof ThrowStmt) return abruptCovers;
        if (statement instanceof IfStmt ifStmt) {
            return ifStmt.getElseStmt().isPresent() && alwaysPuts(ifStmt.getThenStmt(), mapName, key, abruptCovers)
                    && alwaysPuts(ifStmt.getElseStmt().get(), mapName, key, abruptCovers);
        }
        if (statement instanceof TryStmt tryStmt) return alwaysPuts(tryStmt.getTryBlock(), mapName, key, abruptCovers);
        if (statement instanceof DoStmt doStmt) return alwaysPuts(doStmt.getBody(), mapName, key, abruptCovers);
        if (statement instanceof LabeledStmt labeled) return alwaysPuts(labeled.getStatement(), mapName, key, abruptCovers);
        if (statement instanceof SynchronizedStmt sync) return alwaysPuts(sync.getBody(), mapName, key, abruptCovers);
        return false;
    }

    // ================================================================ 작은 도우미

    private static boolean isPutOf(MethodCallExpr call, String mapName, String key) {
        return (call.getNameAsString().equals("put"))
                && call.getArguments().size() == 2
                && call.getScope().map(s -> unwrap(s) instanceof NameExpr n && n.getNameAsString().equals(mapName)).orElse(false)
                && unwrap(call.getArgument(0)) instanceof StringLiteralExpr literal && literal.getValue().equals(key);
    }

    /** {@code map.get("key")} / {@code getOrDefault("key", …)}. 받는 쪽이 없으면 this(BaseParam.getStatement의 this.get). */
    private static boolean isMapGet(MethodCallExpr call) {
        String name = call.getNameAsString();
        return (name.equals("get") || name.equals("getOrDefault"))
                && !call.getArguments().isEmpty()
                && unwrap(call.getArgument(0)) instanceof StringLiteralExpr;
    }

    private static boolean before(Node a, Node b) {
        return a.getBegin().isPresent() && b.getBegin().isPresent() && a.getBegin().get().isBefore(b.getBegin().get());
    }

    /** 구문 파라미터가 List·배열인가. 감싼 메서드의 파라미터면 호출 인자의 타입을 본다. */
    private boolean isCollectionArgument(Expression expression, Frame frame) {
        Expression e = unwrap(expression);
        if (expression instanceof CastExpr cast && isCollectionType(JavaSourceIndex.simpleName(cast.getType()))) return true;
        if (e instanceof NameExpr name) {
            Binding binding = frame.bindings.get(name.getNameAsString());
            Optional<Declaration> declaration = java.declarationOf(name);
            if (binding != null && declaration.isPresent() && declaration.get() instanceof ParamDecl p && p.callable() == frame.method) {
                return isCollectionArgument(binding.arg(), binding.caller());
            }
            String type = declaration.map(java::typeNameOf).orElse(null);
            return type != null && (isCollectionType(type) || type.endsWith("[]"));
        }
        return false;
    }

    private static boolean isCollectionType(String type) {
        return Set.of("List", "ArrayList", "LinkedList", "Collection", "Set", "HashSet").contains(type);
    }

    /** JDK 맵이거나, 우리 소스에서 JDK 맵을 상속한 클래스(요청 DTO가 HashMap을 상속하는 경우)인가. */
    private boolean isMapType(String type) {
        return MAP_TYPES.contains(type) || type.endsWith("Map") || java.extendsAny(type, MAP_TYPES);
    }

    private boolean isLoginInfo(String methodName, String scopeType) {
        return rules.loginMethodPrefixes().stream().anyMatch(methodName::startsWith)
                || (scopeType != null && rules.loginTypeNames().stream().anyMatch(scopeType::contains));
    }

    private static boolean isConstantName(String name) {
        return name.length() > 1 && name.equals(name.toUpperCase()) && name.chars().anyMatch(Character::isLetter);
    }

    private boolean isClassName(NameExpr name) {
        return Character.isUpperCase(name.getNameAsString().charAt(0)) && java.declarationOf(name).isEmpty();
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
        return oneLine.length() > 120 ? oneLine.substring(0, 117) + "..." : oneLine;
    }
}
