package com.sjinc.securitymonitor.service.securecode.trace;

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
import com.sjinc.securitymonitor.service.securecode.trace.ValueOriginTracer.Binding;
import com.sjinc.securitymonitor.service.securecode.trace.ValueOriginTracer.Frame;
import com.sjinc.securitymonitor.service.securecode.trace.ValueOriginTracer.V;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.Declaration;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.FieldDecl;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.LocalDecl;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.ParamDecl;

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
import java.util.TreeSet;
import java.util.stream.Stream;
import com.sjinc.securitymonitor.dto.securecode.DollarVerdict;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.SecureCodeSnippetBuilder;
import com.sjinc.securitymonitor.service.securecode.tracerule.FrameworkProfiler;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;

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
     * @param verdicts      {@code ${}} 한 곳마다 판정 하나(경로·줄 순)
     * @param failedFiles   구문 분석에 실패한 파일 — 그 안의 세팅·호출을 못 봤으니 판정이 덜 정확하다
     * @param genericRoutes 클라이언트가 구문 id를 정하는 공통 실행 경로(근거 표시용)
     * @param scopeVerdicts 사용자 범위 키(TraceRules.userScopeKeys)가 SQL 조건 자리(WHERE·ON·HAVING)에 {@code #{}}로 쓰인 곳마다 판정 하나(경로·줄 순).
     *                      값 자리(INSERT VALUES·UPDATE SET)는 등록자·수정자 기록이라, {@code ${}}는 위 verdicts가 SQL 삽입으로 이미 판정하므로 넣지 않는다
     * @param scopeKeysUsed 이 저장소의 매퍼에 사용자 범위 키가 하나라도 쓰였는가 — 키가 설정돼 있는데 false면 이 시스템의 키가 설정에 없다는 뜻이다
     */
    public record Result(List<DollarVerdict> verdicts, List<String> failedFiles, List<String> genericRoutes,
                         List<DollarVerdict> scopeVerdicts, boolean scopeKeysUsed) {
    }

    /** 구문 실행 메서드 — MyBatis SqlSession과 iBatis 2 SqlMapClient·SqlMapClientTemplate(queryFor…, insert·update·delete는 같은 이름). */
    private static final Set<String> SQL_METHODS = Set.of(
            "selectOne", "selectList", "selectMap", "selectCursor", "select", "insert", "update", "delete",
            "queryForList", "queryForObject", "queryForMap", "queryForPaginatedList", "queryWithRowHandler");
    /** 점검에서 빼는 폴더(SemgrepRunner의 제외 목록과 같은 기준). */
    private static final Set<String> IGNORED_DIRS = Set.of(".git", "target", "build", "out", "node_modules", ".idea", ".gradle");

    private final MapperXmlIndex.MapperFile[] mappers;
    private final JavaSourceIndex java;
    private final TraceRules rules;
    private final ValueOriginTracer origin;
    /**
     * (구문, 키) 판정 재사용. 사용자 범위 키는 거의 모든 구문에 여러 번 쓰여(WHERE·INSERT 값) ${}보다 훨씬 많아서, 같은 구문의 같은 키를
     * 매번 다시 추적하면 점검 시간이 그만큼 는다. 판정은 구문·키·bind 출처로만 정해지므로 줄이 달라도 같다.
     */
    private final Map<String, V> statementKeyMemo = new HashMap<>();

    private MybatisDollarTracer(List<MapperXmlIndex.MapperFile> mappers, JavaSourceIndex java, TraceRules rules) {
        this.mappers = mappers.toArray(MapperXmlIndex.MapperFile[]::new);
        this.java = java;
        this.rules = rules;
        this.origin = new ValueOriginTracer(java, rules);
    }

    /** clone한 저장소를 읽어 판정한다. src/test·빌드 폴더는 Semgrep과 같은 기준으로 뺀다. */
    public static Result trace(Path projectDir, TraceRules rules) throws IOException {
        return trace(readSources(projectDir), rules);
    }

    /**
     * 저장소의 .java·.xml과 설정 파일(application·bootstrap yml/properties, build.gradle)을 읽는다(경로 → 내용). 추적은 .java·.xml만 쓰고,
     * 추적 규칙 초안(TraceRuleDrafter)·프레임워크 구조(FrameworkProfiler)가 설정 파일까지 같은 기준으로 본다.
     */
    public static Map<String, String> readSources(Path projectDir) throws IOException {
        Map<String, String> sources = new TreeMap<>();
        try (Stream<Path> files = Files.walk(projectDir)) {
            for (Path file : (Iterable<Path>) files::iterator) {
                String relative = projectDir.relativize(file).toString().replace('\\', '/');
                if (!Files.isRegularFile(file) || isIgnored(relative)) continue;
                if (relative.endsWith(".java") || relative.endsWith(".xml") || FrameworkProfiler.isConfigFile(relative)) {
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
    public static Result trace(Map<String, String> sources, TraceRules rules) {
        return trace(sources, JavaSourceIndex.fromSources(sources), rules);
    }

    /** 이미 만든 Java 색인을 쓴다 — 점검 한 번에 ${} 추적·위험 호출 추적·추적 규칙 확인이 구문 분석을 한 번만 하게. */
    public static Result trace(Map<String, String> sources, JavaSourceIndex java, TraceRules rules) {
        List<MapperXmlIndex.MapperFile> mappers = new ArrayList<>();
        sources.forEach((path, content) -> {
            if (path.endsWith(".xml")) {
                MapperXmlIndex.MapperFile mapper = MapperXmlIndex.parse(path, content);
                if (mapper != null) mappers.add(mapper);
            }
        });
        return new MybatisDollarTracer(mappers, java, rules).run();
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
        // 정렬해서 돈다 — Set.of는 JVM마다 순회 순서가 달라, 같은 코드인데 근거로 고르는 경로가 실행마다 바뀌었다.
        for (String name : new TreeSet<>(SQL_METHODS)) {
            for (MethodCallExpr call : java.callsNamed(name)) {
                if (!isSqlSink(call)) continue;
                CallableDeclaration<?> method = call.findAncestor(CallableDeclaration.class).orElse(null);
                if (method == null) continue;
                origin.resetBudget();
                for (StatementRef ref : resolveStatement(call.getArgument(0), Frame.root(method), 0)) {
                    Site site = new Site(call, ref.frame(), ref.evidence());
                    if (ref.safety() == TraceSafety.CLIENT) {
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
        List<DollarVerdict> scopeVerdicts = new ArrayList<>();
        Set<String> scopeKeys = rules.userScopeKeys();
        boolean scopeKeysUsed = false;
        for (MapperXmlIndex.MapperFile mapper : mappers) {
            for (MapperXmlIndex.Statement s : mapper.statements()) {
                for (MapperXmlIndex.Dollar d : s.dollars()) {
                    verdicts.add(judge(d, List.of(s.fullId()), sitesByStatement, genericSites));
                    scopeKeysUsed |= isScopeKey(d, scopeKeys);
                }
                for (MapperXmlIndex.Dollar d : s.hashes()) {
                    if (!isScopeKey(d, scopeKeys)) continue;
                    scopeKeysUsed = true;
                    // 값 자리(INSERT VALUES·UPDATE SET)의 사용자 범위 키는 등록자·수정자 기록이라 인가 판정에서 뺀다.
                    if (!d.condition()) continue;
                    scopeVerdicts.add(judge(d, List.of(s.fullId()), sitesByStatement, genericSites));
                }
            }
            for (MapperXmlIndex.Fragment f : mapper.fragments()) {
                List<String> statementIds = includers.getOrDefault(f.fullId(), List.of());
                for (MapperXmlIndex.Dollar d : f.dollars()) {
                    verdicts.add(judge(d, statementIds, sitesByStatement, genericSites));
                    scopeKeysUsed |= isScopeKey(d, scopeKeys);
                }
                for (MapperXmlIndex.Dollar d : f.hashes()) {
                    if (!isScopeKey(d, scopeKeys)) continue;
                    scopeKeysUsed = true;
                    if (!d.condition()) continue;
                    scopeVerdicts.add(judge(d, statementIds, sitesByStatement, genericSites));
                }
            }
        }
        verdicts.sort(BY_LOCATION);
        scopeVerdicts.sort(BY_LOCATION);
        return new Result(verdicts, java.failedFiles(), genericRoutes, scopeVerdicts, scopeKeysUsed);
    }

    private static final java.util.Comparator<DollarVerdict> BY_LOCATION =
            (a, b) -> a.path().equals(b.path()) ? Integer.compare(a.line(), b.line()) : a.path().compareTo(b.path());

    /** 사용자 범위 키를 쓰는가 — 키 자체이거나, bind가 사용자 범위 키로 만든 값이다. */
    private static boolean isScopeKey(MapperXmlIndex.Dollar d, Set<String> scopeKeys) {
        if (scopeKeys.isEmpty()) return false;
        if (scopeKeys.contains(d.key())) return true;
        return d.bindFrom().stream().anyMatch(scopeKeys::contains);
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
        String xmlStep = d.path().substring(d.path().lastIndexOf('/') + 1) + ":" + d.line() + " " + d.display();
        if (d.xmlFixed() != null) {
            return verdict(d, String.join(", ", statementIds), V.of(TraceSafety.XML_FIXED, d.xmlFixed()), xmlStep);
        }
        if (statementIds.isEmpty()) {
            return verdict(d, "", V.of(TraceSafety.UNKNOWN, "이 sql 조각을 include하는 구문이 없음"), xmlStep);
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
        String memoKey = statementId + "\u0000" + d.key() + "\u0000" + d.bindFrom();
        V cached = statementKeyMemo.get(memoKey);
        if (cached == null) {
            cached = judgeStatementUncached(d, statementId, direct, generic);
            statementKeyMemo.put(memoKey, cached);
        }
        return cached;
    }

    private V judgeStatementUncached(MapperXmlIndex.Dollar d, String statementId, List<Site> direct, List<Site> generic) {
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
            return V.of(TraceSafety.UNKNOWN, "이 구문(" + statementId + ")을 실행하는 Java 코드를 찾지 못함");
        }
        if (directV == null) {
            // 직접 부르는 곳이 없고 공통 실행 경로로만 실행된다 — 그 경로의 판정이 곧 결론이다.
            return genericV.safety() == TraceSafety.CLIENT
                    ? genericV.append("직접 호출처 없이 공통 실행 경로로만 실행됨") : genericV;
        }
        if (directV.safety() == TraceSafety.CLIENT || genericV == null || genericV.safety() != TraceSafety.CLIENT) {
            V worst = V.worst(directV, genericV);
            if (worst == directV && genericV != null && worst.safety().isSafe()) {
                // 안전 판정의 근거가 직접 경로뿐이면 "공통 실행 경로는 봤나?"를 알 수 없다(CRM crd020의 ${loginBrndzCd}를 보고 물었다).
                // 그 경로로 와도 안전한 이유(세션 값으로 덮어씀 등)를 한 줄 덧붙인다.
                return worst.append("공통 실행 경로로 이 구문을 직접 불러도 " + genericV.safety().label() + ": "
                        + String.join(" → ", genericV.evidence()));
            }
            return worst;
        }
        // 서비스 경로는 클라이언트 값이 아니지만, 공통 실행 경로로 직접 부르면 클라이언트 값이 들어간다.
        List<String> evidence = new ArrayList<>(directV.evidence());
        evidence.add("그러나 공통 실행 경로로 이 구문을 직접 부르면: " + String.join(" → ", genericV.evidence()));
        return new V(TraceSafety.BYPASSABLE, evidence);
    }

    /** 이 실행 경로에서 key의 출처. 이 경로로는 key에 값이 닿을 수 없으면 null. */
    private V keyAtSite(Site site, String key, String bindNote) {
        origin.resetBudget();
        MethodCallExpr sink = site.sink();
        V v;
        if (sink.getArguments().size() < 2) {
            v = V.of(TraceSafety.SERVER_SET, "파라미터 없이 실행");
        } else if (origin.isCollectionArgument(sink.getArgument(1), site.frame())) {
            // MyBatis는 List·배열 파라미터를 list/collection/array 키로 감싼다 — ${key}는 원소에 닿지 않는다
            // (CRM Syc020Service.saveMenu의 insert(statement, menuData)를 클라이언트 경로로 잘못 잡았었다).
            // 이 실행 경로로는 이 키에 값을 넣을 수 없으니 판정에서 뺀다(null).
            return null;
        } else {
            v = origin.keyOf(sink.getArgument(1), List.of(key), sink, site.frame(), 0);
        }
        v = v.append(java.location(sink) + " " + ValueOriginTracer.abbreviate(sink.toString()));
        return bindNote == null ? v : v.append(bindNote);
    }

    private DollarVerdict verdict(MapperXmlIndex.Dollar d, String statement, V v, String xmlStep) {
        List<String> evidence = new ArrayList<>(v.evidence());
        evidence.add(xmlStep);
        return new DollarVerdict(d.path(), d.line(), statement, d.expr(), d.key(), v.safety(), evidence, d.display());
    }

    // ================================================================ 구문 id 찾기

    /** 구문 실행의 구문 id 출처. id가 있으면 그 구문, safety가 CLIENT면 클라이언트가 구문을 고르는 공통 실행 경로. */
    private record StatementRef(String id, TraceSafety safety, Frame frame, List<String> evidence) {
    }

    private boolean isSqlSink(MethodCallExpr call) {
        if (call.getArguments().isEmpty() || call.getScope().isEmpty() || !java.resolve(call).isEmpty()) return false;
        Expression scope = call.getScope().get();
        String type = java.typeNameOf(scope);
        if (type != null) return type.contains("SqlSession") || type.contains("SqlMap");
        String text = scope.toString().toLowerCase();
        return text.contains("sql") || text.contains("session");
    }

    private List<StatementRef> resolveStatement(Expression expression, Frame frame, int depth) {
        Expression e = ValueOriginTracer.unwrap(expression);
        String constant = origin.constantString(e);
        if (constant != null) {
            return List.of(new StatementRef(constant, TraceSafety.SERVER_SET, frame, List.of()));
        }
        if (depth < ValueOriginTracer.MAX_DEPTH && e instanceof NameExpr name) {
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
                        evidence.add(java.location(call) + " " + ValueOriginTracer.abbreviate(call.toString()));
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
        V v = origin.valueOf(e, frame, depth);
        if (v.safety() == TraceSafety.CLIENT) {
            return List.of(new StatementRef(null, TraceSafety.CLIENT, frame, v.evidence()));
        }
        return List.of();
    }

}
