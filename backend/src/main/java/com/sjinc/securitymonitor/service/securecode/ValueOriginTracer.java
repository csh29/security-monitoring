package com.sjinc.securitymonitor.service.securecode;

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
import com.sjinc.securitymonitor.service.securecode.JavaSourceIndex.Declaration;
import com.sjinc.securitymonitor.service.securecode.JavaSourceIndex.FieldDecl;
import com.sjinc.securitymonitor.service.securecode.JavaSourceIndex.LocalDecl;
import com.sjinc.securitymonitor.service.securecode.JavaSourceIndex.ParamDecl;

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
 * Java 소스에서 값 하나가 어디서 오는지(클라이언트 요청값 / 서버가 정한 값 / 모름) 따라가는 엔진. MyBatis {@code ${}} 연계 추적
 * (MybatisDollarTracer)과 위험 호출 지점 추적(SinkTracer)이 함께 쓴다.
 *
 * <p>따라가는 방법: 지역 변수는 모든 대입, 파라미터는 모든 호출자(호출 문맥 Frame으로 인자를 묶어 감), 맵은 실행 직전까지
 * 모든 경로에서 일어나는 {@code put("key", 값)}(조건부 put이면 원래 값도 본다), 우리 메서드는 반환문, 컨트롤러 요청 매핑
 * 파라미터는 클라이언트 값, 세션 덮어쓰기·로그인 정보는 trace-rules.yml(TraceRules). 끝까지 못 따라가면 UNKNOWN이다
 * — 안전하다고 하지 않는다.
 *
 * <p>Spring 없이 도는 순수 클래스다. 상태(걸음 수·방문 표시)를 들고 있으니 판정 하나를 시작할 때 resetBudget을 부른다.
 */
final class ValueOriginTracer {

    /** 값을 바꾸지 않고 그대로 옮기는 메서드 — 출처는 받는 쪽·인자와 같다. */
    static final Set<String> PROPAGATING_METHODS = Set.of(
            "toString", "trim", "strip", "toUpperCase", "toLowerCase", "substring", "split", "concat", "replace",
            "replaceAll", "intern", "valueOf", "format", "join", "orElse", "ofNullable", "of", "defaultString",
            "defaultIfEmpty", "defaultIfBlank", "nvl", "toArray", "stream", "collect", "getOrDefault",
            // 경로·주소 조립(파일 경로가 어디서 왔는지 따라가기 위함)
            "resolve", "resolveSibling", "normalize", "getAbsolutePath", "getCanonicalPath", "getPath", "toPath", "toFile",
            "toURI", "toURL", "toAbsolutePath", "append");
    /** 생성자 인자로 문자열·경로·주소를 조립하는 타입 — 만든 값의 출처는 인자들의 출처다. */
    static final Set<String> ASSEMBLING_TYPES = Set.of(
            "String", "StringBuilder", "StringBuffer", "File", "URL", "URI", "FileSystemResource", "UrlResource");
    /**
     * 외부와 통신하지 않는 JDK 값 객체(날짜·시간·난수·UUID·숫자). 만든 값·꺼낸 값의 출처는 재료(받는 쪽·인자)의 출처다 —
     * 서버가 날짜·난수로 만든 파일명({@code FrameDateUtil.getTimeLocale(...) + new Random().nextInt()})을 "판정 불가"로 두지 않기 위함.
     * RestTemplate·SqlSession처럼 외부에서 값을 가져오는 객체는 넣지 않는다(응답은 서버가 정한 값이 아니다).
     */
    static final Set<String> PURE_VALUE_TYPES = Set.of(
            "Calendar", "GregorianCalendar", "Date", "TimeZone", "SimpleDateFormat", "DateFormat", "DateTimeFormatter",
            "LocalDate", "LocalDateTime", "LocalTime", "ZonedDateTime", "OffsetDateTime", "Instant", "ZoneId", "Duration",
            "Random", "SecureRandom", "ThreadLocalRandom", "UUID", "Integer", "Long", "Double", "BigDecimal", "BigInteger",
            "Locale", "Optional", "Path", "File");
    static final Set<String> REQUEST_GETTERS = Set.of(
            "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders", "getQueryString",
            "getRequestURI", "getRequestURL", "getCookies", "getPathInfo", "getInputStream", "getReader");
    static final Set<String> NON_CLIENT_PARAM_TYPES = Set.of(
            "HttpServletRequest", "HttpServletResponse", "HttpSession", "Principal", "Authentication",
            "Model", "ModelMap", "BindingResult", "Locale", "RedirectAttributes");
    static final Set<String> MAP_TYPES = Set.of(
            "Map", "HashMap", "LinkedHashMap", "TreeMap", "ConcurrentHashMap");
    /** 실제 저장소에서 갈래가 수십 개로 퍼질 수 있어 한 {@code ${}}당 따라가는 걸음 수를 제한한다. 넘기면 판정 불가. */
    static final int MAX_STEPS = 20_000;
    // 문자열·경로를 .append() 체인으로 조립하면 식 깊이만으로 14단계를 넘었다(CRM 업로드 경로). 폭주는 MAX_STEPS·방문 표시가 막는다.
    static final int MAX_DEPTH = 40;

    final JavaSourceIndex java;
    final TraceRules rules;
    private int steps;
    /** 지금 따라가는 중인 지역 변수(+키 경로). {@code sql = sql + ...}처럼 자기를 참조하는 대입에서 같은 곳을 맴돌지 않게 한다. */
    private final Set<String> visiting = new HashSet<>();


    ValueOriginTracer(JavaSourceIndex java, TraceRules rules) {
        this.java = java;
        this.rules = rules;
    }

    /** 판정 하나를 시작할 때 부른다 — 걸음 수 제한(MAX_STEPS)은 판정마다 센다. */
    void resetBudget() {
        steps = 0;
    }

    // ================================================================ 판정 값

    /** 판정과 근거(출처 → … → 현재 위치 순). */
    record V(TraceSafety safety, List<String> evidence) {
        static V of(TraceSafety safety, String step) {
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
    static final class Frame {
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

    record Binding(Expression arg, Frame caller, MethodCallExpr call) {
    }

    /** 상수 문자열이면 그 값(리터럴, 리터럴끼리 +, static final 문자열 필드). 아니면 null. */
    String constantString(Expression expression) {
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
    V keyOf(Expression mapExpression, List<String> path, Node at, Frame frame, int depth) {
        if (++steps > MAX_STEPS || depth > MAX_DEPTH) {
            return V.of(TraceSafety.UNKNOWN, "추적 범위 초과(" + java.location(at) + ")");
        }
        Expression e = unwrap(mapExpression);
        if (e instanceof NullLiteralExpr) {
            return V.of(TraceSafety.SERVER_SET, "파라미터 없이 실행");
        }
        if (e instanceof ObjectCreationExpr creation && isMapType(creation.getType().getNameAsString())) {
            if (creation.getArguments().isEmpty()) {
                return V.of(TraceSafety.SERVER_SET, java.location(creation) + " 서버가 새로 만든 맵 — " + path.get(0) + " 키 없음");
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
            return V.of(TraceSafety.UNKNOWN, java.location(at) + " this 맵 — 받는 쪽을 모름");
        }
        if (e instanceof NameExpr name) {
            return keyOfName(name, path, at, frame, depth);
        }
        if (e instanceof MethodCallExpr call) {
            // 맵을 만들어 돌려주는 우리 메서드(txtSaveFile = FrameFileUtil.excelToTxt(...)) — 반환문의 맵에서 같은 키를 따라간다
            // (valueOf의 반환문 처리와 같은 방식). 이게 없어 CRM fileMapper의 #{loginEmpNo}가 "맵 출처를 모름"(판정 불가)이 됐다.
            V worst = null;
            for (MethodDeclaration callee : java.resolve(call)) {
                Frame calleeFrame = Frame.call(callee, call, frame);
                for (ReturnStmt ret : returnsOf(callee)) {
                    worst = V.worst(worst, keyOf(ret.getExpression().get(), path, ret, calleeFrame, depth + 1));
                }
            }
            if (worst != null) {
                return worst.append(java.location(call) + " " + abbreviate(call.toString()) + " 반환 맵");
            }
        }
        return V.of(TraceSafety.UNKNOWN, java.location(e) + " 맵 출처를 모름: " + abbreviate(e.toString()));
    }

    /** 메서드의 값 있는 반환문(람다 안의 return은 그 람다의 것이라 뺀다). */
    private static List<ReturnStmt> returnsOf(MethodDeclaration callee) {
        return callee.findAll(ReturnStmt.class).stream()
                .filter(r -> r.findAncestor(LambdaExpr.class).isEmpty() && r.getExpression().isPresent())
                .toList();
    }

    V keyOfName(NameExpr name, List<String> path, Node at, Frame frame, int depth) {
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

    V originKey(NameExpr name, Optional<Declaration> declaration, List<String> path, Node at, Frame frame, int depth) {
        String mapName = name.getNameAsString();
        Binding binding = frame.bindings.get(mapName);
        if (binding != null && declaration.isPresent() && declaration.get() instanceof ParamDecl p && p.callable() == frame.method) {
            return keyOf(binding.arg(), path, binding.call(), binding.caller(), depth + 1)
                    .append(java.location(binding.call()) + " " + abbreviate(binding.call().toString()));
        }
        if (declaration.isEmpty()) {
            return V.of(TraceSafety.UNKNOWN, java.location(name) + " " + mapName + " 선언을 찾지 못함");
        }
        Declaration decl = declaration.get();
        if (decl instanceof ParamDecl param) {
            if (java.isHandler(param.callable())) {
                return clientMap(param, path);
            }
            if (!(param.callable() instanceof MethodDeclaration method)) {
                return V.of(TraceSafety.UNKNOWN, java.location(param.parameter()) + " 생성자 파라미터");
            }
            List<MethodCallExpr> callers = java.callersOf(method);
            if (callers.isEmpty()) {
                return V.of(TraceSafety.UNKNOWN, java.location(method) + " " + method.getNameAsString() + "() 호출처를 찾지 못함");
            }
            V worst = null;
            for (MethodCallExpr call : callers) {
                CallableDeclaration<?> caller = call.findAncestor(CallableDeclaration.class).orElse(null);
                if (caller == null || param.index() >= call.getArguments().size()) continue;
                V v = keyOf(call.getArgument(param.index()), path, call, Frame.root(caller), depth + 1)
                        .append(java.location(call) + " " + abbreviate(call.toString()));
                worst = V.worst(worst, v);
                if (worst.safety() == TraceSafety.CLIENT) break;
            }
            return worst != null ? worst : V.of(TraceSafety.UNKNOWN, method.getNameAsString() + "() 호출처를 찾지 못함");
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
                return V.of(TraceSafety.UNKNOWN, java.location(local.variable()) + " " + mapName + " 값이 정해지는 곳을 모름");
            }
            String mark = System.identityHashCode(local.variable()) + ":" + path;
            if (!visiting.add(mark)) {
                return V.of(TraceSafety.SERVER_SET, java.location(name) + " " + mapName + " (자기 참조)");
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
        return V.of(TraceSafety.UNKNOWN, java.location(name) + " 필드·람다 변수 " + mapName + " — 값이 정해지는 곳을 모름");
    }

    /** 컨트롤러가 요청으로 받은 맵. 세션 덮어쓰기(trace-rules.yml) 대상 키만 안전하다. */
    V clientMap(ParamDecl param, List<String> path) {
        CallableDeclaration<?> handler = param.callable();
        String label = java.location(handler) + " " + java.handlerLabel(handler) + " (" + param.parameter() + ")";
        if (NON_CLIENT_PARAM_TYPES.contains(JavaSourceIndex.simpleName(param.parameter().getType()))) {
            return V.of(TraceSafety.UNKNOWN, label + " — 요청 맵이 아님");
        }
        String key = path.get(path.size() - 1);
        for (TraceRules.SessionOverwrite rule : rules.sessionOverwrites()) {
            if (overwrites(rule, handler, path)) {
                return V.of(TraceSafety.SESSION_OVERWRITE, label + " " + rule.name() + "가 " + key + "를 세션 값으로 덮어씀");
            }
        }
        return V.of(TraceSafety.CLIENT, label + " — 클라이언트가 보낸 " + String.join(".", path));
    }

    /** 이 요청 매핑에서 rule이 path(요청 맵 기준 키 경로)를 세션 값으로 덮어쓰는가. */
    static boolean overwrites(TraceRules.SessionOverwrite rule, CallableDeclaration<?> handler, List<String> path) {
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

    V valueOf(Expression expression, Frame frame, int depth) {
        if (++steps > MAX_STEPS || depth > MAX_DEPTH) {
            return V.of(TraceSafety.UNKNOWN, "추적 범위 초과(" + java.location(expression) + ")");
        }
        Expression e = unwrap(expression);
        if (e instanceof LiteralExpr) {
            return V.of(TraceSafety.SERVER_SET, java.location(e) + " 상수 " + abbreviate(e.toString()));
        }
        if (e instanceof ConditionalExpr conditional) {
            return V.worst(valueOf(conditional.getThenExpr(), frame, depth + 1), valueOf(conditional.getElseExpr(), frame, depth + 1));
        }
        if (e instanceof BinaryExpr binary) {
            if (binary.getOperator() != BinaryExpr.Operator.PLUS) {
                return V.of(TraceSafety.SERVER_SET, java.location(e) + " 비교·연산 결과");
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
            // 클래스에 붙은 정적 필드(File.separator, StandardCharsets.UTF_8, HttpMethod.GET)는 라이브러리 상수다.
            boolean classField = access.getScope() instanceof NameExpr cls && isClassName(cls);
            if (classField || isConstantName(access.getNameAsString())) {
                return V.of(TraceSafety.SERVER_SET, java.location(e) + " 상수 " + access);
            }
            return V.of(TraceSafety.UNKNOWN, java.location(e) + " 필드 " + access + " — 값이 정해지는 곳을 모름");
        }
        if (e.isArrayAccessExpr()) {
            return valueOf(e.asArrayAccessExpr().getName(), frame, depth + 1);
        }
        // 문자열·경로·주소를 조립하는 생성자는 인자들의 출처를 그대로 갖는다(new File(dir, name)의 name이 요청값이면 요청값).
        if (e instanceof ObjectCreationExpr creation && (ASSEMBLING_TYPES.contains(creation.getType().getNameAsString())
                || PURE_VALUE_TYPES.contains(creation.getType().getNameAsString()))) {
            return worstOf(creation.getArguments(), frame, depth, V.of(TraceSafety.SERVER_SET, java.location(e) + " 빈 값"));
        }
        if (e instanceof MethodCallExpr call) {
            return valueOfCall(call, frame, depth);
        }
        return V.of(TraceSafety.UNKNOWN, java.location(e) + " 해석하지 못한 식: " + abbreviate(e.toString()));
    }

    V valueOfName(NameExpr name, Frame frame, int depth) {
        String id = name.getNameAsString();
        Optional<Declaration> declaration = java.declarationOf(name);
        Binding binding = frame.bindings.get(id);
        if (binding != null && declaration.isPresent() && declaration.get() instanceof ParamDecl p && p.callable() == frame.method) {
            return valueOf(binding.arg(), binding.caller(), depth + 1)
                    .append(java.location(binding.call()) + " " + abbreviate(binding.call().toString()));
        }
        if (declaration.isEmpty()) {
            return isConstantName(id) ? V.of(TraceSafety.SERVER_SET, java.location(name) + " 상수 " + id)
                    : V.of(TraceSafety.UNKNOWN, java.location(name) + " " + id + " 선언을 찾지 못함");
        }
        Declaration decl = declaration.get();
        if (decl instanceof ParamDecl param) {
            if (java.isHandler(param.callable())) {
                String type = JavaSourceIndex.simpleName(param.parameter().getType());
                if (NON_CLIENT_PARAM_TYPES.contains(type)) {
                    return V.of(TraceSafety.UNKNOWN, java.location(param.parameter()) + " " + param.parameter());
                }
                return V.of(TraceSafety.CLIENT, java.location(param.callable()) + " " + java.handlerLabel(param.callable())
                        + " (" + param.parameter() + ") — 클라이언트가 보낸 값");
            }
            if (!(param.callable() instanceof MethodDeclaration method)) {
                return V.of(TraceSafety.UNKNOWN, java.location(param.parameter()) + " 생성자 파라미터 " + id);
            }
            List<MethodCallExpr> callers = java.callersOf(method);
            if (callers.isEmpty()) {
                return V.of(TraceSafety.UNKNOWN, java.location(method) + " " + method.getNameAsString() + "() 호출처를 찾지 못함");
            }
            V worst = null;
            for (MethodCallExpr call : callers) {
                CallableDeclaration<?> caller = call.findAncestor(CallableDeclaration.class).orElse(null);
                if (caller == null || param.index() >= call.getArguments().size()) continue;
                worst = V.worst(worst, valueOf(call.getArgument(param.index()), Frame.root(caller), depth + 1)
                        .append(java.location(call) + " " + abbreviate(call.toString())));
                if (worst.safety() == TraceSafety.CLIENT) break;
            }
            return worst != null ? worst : V.of(TraceSafety.UNKNOWN, method.getNameAsString() + "() 호출처를 찾지 못함");
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
                return V.of(TraceSafety.UNKNOWN, java.location(local.variable()) + " " + id + " 값이 정해지는 곳을 모름");
            }
            String mark = System.identityHashCode(local.variable()) + ":value";
            if (!visiting.add(mark)) {
                // 이미 따라가는 중 — 나머지 대입들이 판정을 정한다(이 갈래는 판정에 보태지 않는다).
                return V.of(TraceSafety.SERVER_SET, java.location(name) + " " + id + " (자기 참조)");
            }
            try {
                V v = worstOf(sources, frame, depth, null);
                // 여러 곳에서 대입하는데 모두 안전하면 근거에 그 사실을 남긴다 — 첫 대입(String url = "")만 보이면 이유가 안 읽힌다.
                return v.safety().isSafe() && sources.size() > 1
                        ? v.append(java.location(name) + " " + id + " — 대입 " + sources.size() + "곳 모두 서버 값") : v;
            } finally {
                visiting.remove(mark);
            }
        }
        if (decl instanceof FieldDecl field) {
            if (JavaSourceIndex.hasAnnotation(field.field(), "Value")) {
                return V.of(TraceSafety.SERVER_SET, java.location(field.variable()) + " 설정값(@Value) " + id);
            }
            if (field.field().isFinal() && field.variable().getInitializer().isPresent()) {
                return valueOf(field.variable().getInitializer().get(), frame, depth + 1);
            }
            if (isConstantName(id)) {
                return V.of(TraceSafety.SERVER_SET, java.location(field.variable()) + " 상수 " + id);
            }
            return V.of(TraceSafety.UNKNOWN, java.location(field.variable()) + " 필드 " + id + " — 값이 정해지는 곳을 모름");
        }
        return V.of(TraceSafety.UNKNOWN, java.location(name) + " 람다·catch 변수 " + id);
    }

    V valueOfCall(MethodCallExpr call, Frame frame, int depth) {
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
            return V.of(TraceSafety.SERVER_SET, location + " 로그인 정보 " + abbreviate(call.toString()));
        }
        if (REQUEST_GETTERS.contains(name) && "HttpServletRequest".equals(scopeType)) {
            return V.of(TraceSafety.CLIENT, location + " 요청 값 " + abbreviate(call.toString()));
        }
        List<MethodDeclaration> callees = java.resolve(call);
        if (!callees.isEmpty()) {
            // 우리 메서드면 반환문들을 본다(getTableNm처럼 모든 분기가 상수를 반환하면 상수).
            V worst = null;
            for (MethodDeclaration callee : callees) {
                Frame calleeFrame = Frame.call(callee, call, frame);
                for (ReturnStmt ret : returnsOf(callee)) {
                    worst = V.worst(worst, valueOf(ret.getExpression().get(), calleeFrame, depth + 1));
                }
            }
            return worst == null ? V.of(TraceSafety.UNKNOWN, location + " " + name + "() 반환값을 모름")
                    : worst.append(location + " " + abbreviate(call.toString()) + " 반환값");
        }
        // Paths.get(a, b)·Path.of(...)는 인자로 경로를 조립한다.
        boolean pathFactory = (name.equals("get") || name.equals("of"))
                && scope.map(s -> s.toString().equals("Paths") || s.toString().equals("Path")).orElse(false);
        if (PROPAGATING_METHODS.contains(name) || pathFactory) {
            List<Expression> parts = new ArrayList<>(call.getArguments());
            scope.filter(s -> !(s instanceof NameExpr n && isClassName(n))).ifPresent(parts::add);
            return worstOf(parts, frame, depth, V.of(TraceSafety.SERVER_SET, location + " " + name + "()"));
        }
        // 클래스에 부르는 외부 정적 메서드(UUID.randomUUID(), System.currentTimeMillis(), Base64.encode(x))는 인자들의 출처를 따른다
        // — 인자가 없으면 서버가 만든 값이다. 서버가 UUID로 파일명을 만드는 안전한 코드를 "판정 불가"로 두지 않기 위함.
        if (scope.isPresent() && scope.get() instanceof NameExpr cls && isClassName(cls)) {
            return worstOf(call.getArguments(), frame, depth, V.of(TraceSafety.SERVER_SET, location + " 서버가 만든 값 " + abbreviate(call.toString())));
        }
        // JDK 값 객체의 메서드(cal.getTime(), formater.format(date), new Random().nextInt(n))는 받는 쪽·인자의 출처를 따른다.
        if (scope.isPresent() && scopeType != null && PURE_VALUE_TYPES.contains(scopeType)) {
            List<Expression> parts = new ArrayList<>(call.getArguments());
            parts.add(scope.get());
            return worstOf(parts, frame, depth, null).append(location + " " + abbreviate(call.toString()));
        }
        // 모르는 외부 메서드라도 받는 쪽이 클라이언트가 보낸 객체면(업로드 파일의 getOriginalFilename()) 꺼낸 값도 클라이언트 값이다.
        if (scope.isPresent() && !(scope.get() instanceof NameExpr n && isClassName(n))) {
            V receiver = valueOf(scope.get(), frame, depth + 1);
            if (receiver.safety() == TraceSafety.CLIENT) {
                return receiver.append(location + " " + abbreviate(call.toString()) + " — 클라이언트가 보낸 객체에서 꺼낸 값");
            }
        }
        return V.of(TraceSafety.UNKNOWN, location + " 외부 메서드 " + abbreviate(call.toString()));
    }

    V worstOf(List<? extends Expression> expressions, Frame frame, int depth, V whenEmpty) {
        V worst = null;
        for (Expression expression : expressions) {
            worst = V.worst(worst, valueOf(expression, frame, depth + 1));
            if (worst.safety() == TraceSafety.CLIENT) break;
        }
        return worst != null ? worst : whenEmpty;
    }

    // ================================================================ 실행 경로

    /**
     * put이 at보다 먼저, 그리고 at에 도달하는 모든 경로에서 실행되는가. put에서 위로 올라가며 at과 공통 조상에 닿기 전에
     * 조건(if 한쪽, 반복, catch, 람다, 삼항, &&·||)이 끼면 조건부다. 단 if/else 양쪽이 모두 같은 키를 넣으면(또는 반대쪽이
     * return·throw로 끝나 at에 못 오면) 그 if는 조건이 아니다.
     */
    static boolean mustExecuteBefore(Node put, Node at, String mapName, String key) {
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
    static boolean alwaysPuts(Statement statement, String mapName, String key, boolean abruptCovers) {
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

    static boolean isPutOf(MethodCallExpr call, String mapName, String key) {
        return (call.getNameAsString().equals("put"))
                && call.getArguments().size() == 2
                && call.getScope().map(s -> unwrap(s) instanceof NameExpr n && n.getNameAsString().equals(mapName)).orElse(false)
                && unwrap(call.getArgument(0)) instanceof StringLiteralExpr literal && literal.getValue().equals(key);
    }

    /** {@code map.get("key")} / {@code getOrDefault("key", …)}. 받는 쪽이 없으면 this(BaseParam.getStatement의 this.get). */
    static boolean isMapGet(MethodCallExpr call) {
        String name = call.getNameAsString();
        int args = call.getArguments().size();
        // Map.get은 인자 1개, getOrDefault는 2개. Paths.get("/data/x")처럼 클래스에 부르는 정적 get은 맵 조회가 아니다.
        return ((name.equals("get") && args == 1) || (name.equals("getOrDefault") && args == 2))
                && unwrap(call.getArgument(0)) instanceof StringLiteralExpr
                && !call.getScope().map(s -> s instanceof NameExpr n && Character.isUpperCase(n.getNameAsString().charAt(0))
                        && !n.getNameAsString().equals(n.getNameAsString().toUpperCase())).orElse(false);
    }

    static boolean before(Node a, Node b) {
        return a.getBegin().isPresent() && b.getBegin().isPresent() && a.getBegin().get().isBefore(b.getBegin().get());
    }

    /** 구문 파라미터가 List·배열인가. 감싼 메서드의 파라미터면 호출 인자의 타입을 본다. */
    boolean isCollectionArgument(Expression expression, Frame frame) {
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

    static boolean isCollectionType(String type) {
        return Set.of("List", "ArrayList", "LinkedList", "Collection", "Set", "HashSet").contains(type);
    }

    /** JDK 맵이거나, 우리 소스에서 JDK 맵을 상속한 클래스(요청 DTO가 HashMap을 상속하는 경우)인가. */
    boolean isMapType(String type) {
        return MAP_TYPES.contains(type) || type.endsWith("Map") || java.extendsAny(type, MAP_TYPES);
    }

    boolean isLoginInfo(String methodName, String scopeType) {
        return rules.loginMethodPrefixes().stream().anyMatch(methodName::startsWith)
                || (scopeType != null && rules.loginTypeNames().stream().anyMatch(scopeType::contains));
    }

    static boolean isConstantName(String name) {
        return name.length() > 1 && name.equals(name.toUpperCase()) && name.chars().anyMatch(Character::isLetter);
    }

    boolean isClassName(NameExpr name) {
        return Character.isUpperCase(name.getNameAsString().charAt(0)) && java.declarationOf(name).isEmpty();
    }

    static Expression unwrap(Expression expression) {
        Expression e = expression;
        while (true) {
            if (e instanceof EnclosedExpr enclosed) e = enclosed.getInner();
            else if (e instanceof CastExpr cast) e = cast.getExpression();
            else return e;
        }
    }

    static String abbreviate(String code) {
        String oneLine = code.replaceAll("\\s+", " ");
        return oneLine.length() > 120 ? oneLine.substring(0, 117) + "..." : oneLine;
    }
}
