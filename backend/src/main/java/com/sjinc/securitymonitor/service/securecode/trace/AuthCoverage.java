package com.sjinc.securitymonitor.service.securecode.trace;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import com.sjinc.securitymonitor.service.securecode.SecureCodeSnippetBuilder;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 엔드포인트별 인증 적용 판정(CWE-306). 인터셉터·필터 등록과 적용 경로를 읽어 인증 장치 후보를 내고({@link #candidates}),
 * 사람이 인정한 장치(trace-rules.yml authDevices)가 적용되지 않는 요청 처리 메서드를 탐지로 낸다({@link #judge}).
 * Spring Security·AOP·컨트롤러 직접 검사·앱 밖 인증은 보지 않으며, 후보가 없으면 판정하지 않는다.
 */
public final class AuthCoverage {

    /** 이 판정이 만드는 탐지의 규칙 id. Semgrep 규칙 폴더에는 없다 — 판정했을 때만 활성 규칙에 넣는다(SecureCodeScanService). */
    public static final String RULE_ID = "kisa-authn-unprotected-endpoint";
    static final String KISA_CATEGORY = "보안기능";
    static final String KISA_NAME = "적절한 인증 없는 중요 기능 허용";
    static final String CWE = "CWE-306";
    static final String SEVERITY = "MEDIUM";

    /** 장치의 종류 — 경로 패턴 문법이 다르다(인터셉터는 Ant, 필터는 서블릿 url-pattern). */
    public enum Kind {
        INTERCEPTOR("인터셉터"), FILTER("필터");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /**
     * 인증을 끼울 수 있는 자리에 등록된 장치 하나.
     *
     * @param className     장치 클래스의 단순 이름
     * @param include       적용 경로 패턴
     * @param exclude       제외 경로 패턴
     * @param patternsKnown 경로 패턴을 모두 읽었는가(상수가 아닌 값으로 정하면 false — 그 장치로는 판정하지 않는다)
     * @param registration  등록한 곳("파일:줄 …")
     */
    public record Hook(Kind kind, String className, List<String> include, List<String> exclude, boolean patternsKnown,
                       String registration) {

        boolean covers(String path) {
            return include.stream().anyMatch(p -> matches(kind, p, path)) && exclude.stream().noneMatch(p -> matches(kind, p, path));
        }

        String describe() {
            return kind.label() + " " + className + " (적용 " + include + (exclude.isEmpty() ? "" : ", 제외 " + exclude) + " — " + registration + ")";
        }
    }

    /** 인증 장치 후보 — 등록된 장치 중 본문이 로그인 정보를 읽고 없으면 막는 것. evidence는 읽는 줄·막는 줄·등록한 곳. */
    public record Candidate(String className, List<String> evidence) {
    }

    /** 요청 처리 메서드 하나. paths는 클래스·메서드 매핑을 합친 경로(여럿일 수 있다). */
    public record Endpoint(String filePath, int line, String httpMethod, List<String> paths, String handler) {
    }

    /** 인증 장치가 적용되지 않는 요청 처리 메서드와 그 이유(경로마다). */
    public record Unprotected(Endpoint endpoint, List<String> reasons) {
    }

    /**
     * 판정 결과.
     *
     * @param judged      판정했는가 — 인정된 장치를 찾았고 그 경로 패턴을 모두 읽었을 때만. false면 탐지를 내지 않는다(활성 규칙에도 넣지 않는다)
     * @param unprotected 인증 장치가 적용되지 않는 요청 처리 메서드
     * @param endpoints   대조한 요청 처리 메서드 수
     * @param notes       점검 완료 알림에 붙일 안내
     */
    public record Result(boolean judged, List<Unprotected> unprotected, int endpoints, List<String> notes) {
    }

    private static final AntPathMatcher ANT = new AntPathMatcher();
    private static final Set<String> INTERCEPTOR_ENTRY = Set.of("preHandle");
    private static final Set<String> FILTER_ENTRY = Set.of("doFilter", "doFilterInternal");
    /** 로그인 정보를 읽는 호출(세션·헤더 토큰·쿠키·서블릿 인증 주체). */
    private static final Pattern READS_CREDENTIAL = Pattern.compile(
            "\\b(getSession|getAttribute|getHeader|getCookies|getUserPrincipal|getRemoteUser|getAuthType)\\s*\\(");
    /** 없으면 막는 동작. 필터의 return;은 chain.doFilter를 부르지 않고 끝내는 것이다. */
    private static final Pattern BLOCKS = Pattern.compile(
            "\\breturn\\s+false\\b|\\bsendRedirect\\s*\\(|\\bsendError\\s*\\(|\\bsetStatus\\s*\\(|\\bthrow\\s+new\\b|\\.forward\\s*\\(");
    private static final Pattern FILTER_RETURN = Pattern.compile("\\breturn\\s*;");
    private static final Map<String, String> MAPPING_METHODS = Map.of(
            "GetMapping", "GET", "PostMapping", "POST", "PutMapping", "PUT", "DeleteMapping", "DELETE", "PatchMapping", "PATCH",
            "RequestMapping", "ALL");
    private static final Pattern XML_COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);
    private static final Pattern MVC_INTERCEPTORS = Pattern.compile("<mvc:interceptors\\b[^>]*>(.*?)</mvc:interceptors>", Pattern.DOTALL);
    private static final Pattern MVC_INTERCEPTOR = Pattern.compile("<mvc:interceptor\\b[^>]*>(.*?)</mvc:interceptor>", Pattern.DOTALL);
    private static final Pattern MVC_MAPPING = Pattern.compile("<mvc:mapping\\s+path\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern MVC_EXCLUDE = Pattern.compile("<mvc:exclude-mapping\\s+path\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern BEAN_CLASS = Pattern.compile("<bean\\b[^>]*?\\bclass\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern BEAN_REF = Pattern.compile("<ref\\s+bean\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern BEAN_ID_CLASS = Pattern.compile("<bean\\b(?=[^>]*\\bid\\s*=\\s*\"([^\"]+)\")(?=[^>]*\\bclass\\s*=\\s*\"([^\"]+)\")[^>]*>");
    private static final Pattern FILTER_DEF = Pattern.compile("<filter>(.*?)</filter>", Pattern.DOTALL);
    private static final Pattern FILTER_MAPPING = Pattern.compile("<filter-mapping>(.*?)</filter-mapping>", Pattern.DOTALL);
    private static final Pattern FILTER_NAME = Pattern.compile("<filter-name>\\s*([^<]+?)\\s*</filter-name>");
    private static final Pattern FILTER_CLASS = Pattern.compile("<filter-class>\\s*([^<]+?)\\s*</filter-class>");
    private static final Pattern URL_PATTERN = Pattern.compile("<url-pattern>\\s*([^<]+?)\\s*</url-pattern>");
    private static final Pattern SERVLET_NAME = Pattern.compile("<servlet-name>\\s*([^<]+?)\\s*</servlet-name>");
    private static final int MAX_CONSTANT_DEPTH = 4;
    private static final int MAX_MESSAGE_LENGTH = 1000;

    private AuthCoverage() {
    }

    // ================================================================ 자리(장치 등록)

    /** 저장소에 등록된 인터셉터·필터와 적용 경로. 같은 장치를 두 곳에서 등록하면 둘 다 나온다. */
    public static List<Hook> hooks(Map<String, String> sources, JavaSourceIndex java) {
        List<Hook> hooks = new ArrayList<>();
        javaInterceptors(java, hooks);
        Map<String, String> beanClasses = new LinkedHashMap<>();
        sources.forEach((path, content) -> {
            if (!path.endsWith(".xml") || !content.contains("<bean")) return;
            Matcher m = BEAN_ID_CLASS.matcher(stripComments(content));
            while (m.find()) beanClasses.putIfAbsent(m.group(1), simpleClass(m.group(2)));
        });
        sources.forEach((path, content) -> {
            if (!path.endsWith(".xml")) return;
            String xml = stripComments(content);
            if (xml.contains("<mvc:interceptors")) xmlInterceptors(path, xml, beanClasses, hooks);
            if (fileName(path).equals("web.xml")) webXmlFilters(path, xml, hooks);
        });
        for (ClassOrInterfaceDeclaration type : sorted(java.allClasses())) {
            for (AnnotationExpr a : type.getAnnotations()) {
                if (!a.getNameAsString().equals("WebFilter")) continue;
                List<String> patterns = new ArrayList<>();
                boolean known = annotationStrings(a, Set.of("value", "urlPatterns"), java, patterns);
                hooks.add(new Hook(Kind.FILTER, type.getNameAsString(), patterns.isEmpty() ? List.of("/*") : patterns, List.of(), known,
                        java.location(a) + " " + abbreviate(a.toString())));
            }
        }
        return hooks;
    }

    private static void javaInterceptors(JavaSourceIndex java, List<Hook> hooks) {
        for (ClassOrInterfaceDeclaration type : sorted(java.allClasses())) {
            for (MethodDeclaration method : type.getMethodsByName("addInterceptors")) {
                for (MethodCallExpr add : method.findAll(MethodCallExpr.class)) {
                    if (!add.getNameAsString().equals("addInterceptor") || add.getArguments().isEmpty()) continue;
                    String target = interceptorClass(add.getArgument(0), java);
                    List<String> include = new ArrayList<>();
                    List<String> exclude = new ArrayList<>();
                    boolean known = true;
                    // registry.addInterceptor(x).addPathPatterns(..).excludePathPatterns(..) — 사슬 위쪽 호출이 이 등록의 설정이다.
                    Node current = add;
                    while (current.getParentNode().orElse(null) instanceof MethodCallExpr outer
                            && outer.getScope().isPresent() && outer.getScope().get() == current) {
                        String name = outer.getNameAsString();
                        if (name.equals("addPathPatterns") || name.equals("excludePathPatterns")) {
                            List<String> target2 = name.equals("addPathPatterns") ? include : exclude;
                            for (Expression arg : outer.getArguments()) known &= strings(arg, java, target2, 0);
                        }
                        current = outer;
                    }
                    hooks.add(new Hook(Kind.INTERCEPTOR, target, include.isEmpty() ? List.of("/**") : include, exclude, known,
                            java.location(add) + " " + abbreviate(current.toString())));
                }
            }
        }
    }

    /** addInterceptor 인자의 클래스 — new X(), 주입 필드(X x), 빈 메서드 x() 반환 타입. 모르면 식 그대로. */
    private static String interceptorClass(Expression arg, JavaSourceIndex java) {
        if (arg instanceof ObjectCreationExpr created) return created.getType().getNameAsString();
        if (arg instanceof MethodCallExpr call) {
            for (MethodDeclaration m : java.resolve(call)) return JavaSourceIndex.simpleName(m.getType());
        }
        String type = java.typeNameOf(arg);
        return type != null ? type : arg.toString();
    }

    private static void xmlInterceptors(String path, String xml, Map<String, String> beanClasses, List<Hook> hooks) {
        Matcher block = MVC_INTERCEPTORS.matcher(xml);
        while (block.find()) {
            String inside = block.group(1);
            int base = block.start(1);
            Matcher one = MVC_INTERCEPTOR.matcher(inside);
            StringBuilder global = new StringBuilder(inside);
            while (one.find()) {
                String body = one.group(1);
                List<String> include = all(MVC_MAPPING, body);
                List<String> exclude = all(MVC_EXCLUDE, body);
                String cls = beanOf(body, beanClasses);
                if (cls != null) {
                    hooks.add(new Hook(Kind.INTERCEPTOR, cls, include.isEmpty() ? List.of("/**") : include, exclude, true,
                            fileName(path) + ":" + lineOf(xml, base + one.start()) + " <mvc:interceptor> " + cls));
                }
                for (int i = one.start(); i < one.end(); i++) global.setCharAt(i, ' ');
            }
            // <mvc:interceptor>로 감싸지 않고 바로 둔 빈은 모든 요청에 적용된다.
            Matcher direct = Pattern.compile(BEAN_CLASS.pattern() + "|" + BEAN_REF.pattern()).matcher(global);
            while (direct.find()) {
                String cls = direct.group(1) != null ? simpleClass(direct.group(1)) : beanClasses.getOrDefault(direct.group(2), direct.group(2));
                hooks.add(new Hook(Kind.INTERCEPTOR, cls, List.of("/**"), List.of(), true,
                        fileName(path) + ":" + lineOf(xml, base + direct.start()) + " <mvc:interceptors> " + cls));
            }
        }
    }

    private static String beanOf(String body, Map<String, String> beanClasses) {
        Matcher bean = BEAN_CLASS.matcher(body);
        if (bean.find()) return simpleClass(bean.group(1));
        Matcher ref = BEAN_REF.matcher(body);
        return ref.find() ? beanClasses.getOrDefault(ref.group(1), ref.group(1)) : null;
    }

    private static void webXmlFilters(String path, String xml, List<Hook> hooks) {
        Map<String, String> classes = new LinkedHashMap<>();
        Matcher def = FILTER_DEF.matcher(xml);
        while (def.find()) {
            Matcher name = FILTER_NAME.matcher(def.group(1));
            Matcher cls = FILTER_CLASS.matcher(def.group(1));
            if (name.find() && cls.find()) classes.put(name.group(1), simpleClass(cls.group(1)));
        }
        Matcher mapping = FILTER_MAPPING.matcher(xml);
        while (mapping.find()) {
            Matcher name = FILTER_NAME.matcher(mapping.group(1));
            if (!name.find() || !classes.containsKey(name.group(1))) continue;
            List<String> patterns = all(URL_PATTERN, mapping.group(1));
            // 서블릿 이름으로 건 매핑은 그 서블릿이 받는 요청 전부로 본다.
            if (patterns.isEmpty() && SERVLET_NAME.matcher(mapping.group(1)).find()) patterns = List.of("/*");
            hooks.add(new Hook(Kind.FILTER, classes.get(name.group(1)), patterns, List.of(), true,
                    fileName(path) + ":" + lineOf(xml, mapping.start()) + " <filter-mapping> " + name.group(1)));
        }
    }

    // ================================================================ 인증 장치 후보

    /** 본문(preHandle·doFilter와 같은 클래스 호출)이 로그인 정보를 읽고 없으면 막는 장치. 모양만 보므로 사람이 근거를 보고 인정한다. */
    public static List<Candidate> candidates(List<Hook> hooks, Map<String, String> sources, JavaSourceIndex java) {
        Map<String, Candidate> found = new LinkedHashMap<>();
        for (Hook hook : hooks) {
            if (found.containsKey(hook.className())) continue;
            for (ClassOrInterfaceDeclaration type : java.allClasses()) {
                if (!type.getNameAsString().equals(hook.className())) continue;
                Set<String> entries = hook.kind() == Kind.INTERCEPTOR ? INTERCEPTOR_ENTRY : FILTER_ENTRY;
                for (MethodDeclaration entry : type.getMethods()) {
                    if (!entries.contains(entry.getNameAsString()) || entry.getBody().isEmpty()) continue;
                    List<MethodDeclaration> bodies = new ArrayList<>(List.of(entry));
                    for (MethodCallExpr call : entry.findAll(MethodCallExpr.class)) {
                        java.resolve(call).stream().filter(m -> m.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null) == type)
                                .forEach(m -> { if (!bodies.contains(m)) bodies.add(m); });
                    }
                    String reads = firstLine(bodies, READS_CREDENTIAL, sources, java);
                    String blocks = firstLine(bodies, BLOCKS, sources, java);
                    if (blocks == null && hook.kind() == Kind.FILTER) blocks = firstLine(bodies, FILTER_RETURN, sources, java);
                    if (reads != null && blocks != null) {
                        found.put(hook.className(), new Candidate(hook.className(), List.of(
                                "로그인 정보 읽기: " + reads, "없으면 막기: " + blocks, "등록: " + hook.describe())));
                    }
                }
            }
        }
        return new ArrayList<>(found.values());
    }

    /** 메서드 본문 원문(파일의 그 줄들)에서 패턴이 처음 나오는 줄("파일:줄 코드"). 주석 줄은 뺀다. */
    private static String firstLine(List<MethodDeclaration> bodies, Pattern pattern, Map<String, String> sources, JavaSourceIndex java) {
        for (MethodDeclaration method : bodies) {
            String path = java.pathOf(method);
            if (path == null || method.getRange().isEmpty() || !sources.containsKey(path)) continue;
            String[] lines = sources.get(path).split("\\R", -1);
            int from = method.getRange().get().begin.line, to = Math.min(method.getRange().get().end.line, lines.length);
            for (int no = from; no <= to; no++) {
                String line = lines[no - 1].strip();
                if (line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) continue;
                if (pattern.matcher(line).find()) return fileName(path) + ":" + no + " " + abbreviate(line);
            }
        }
        return null;
    }

    // ================================================================ 판정

    /** 인정된 장치로 모든 요청 처리 메서드의 경로를 대조한다. 장치를 못 찾거나 경로를 못 읽으면 판정하지 않는다(0건 오해 방지). */
    public static Result judge(Map<String, String> sources, JavaSourceIndex java, Set<String> devices) {
        List<String> notes = new ArrayList<>();
        if (devices.isEmpty()) return new Result(false, List.of(), 0, notes);
        List<Hook> applied = hooks(sources, java).stream().filter(h -> devices.contains(h.className())).toList();
        Set<String> registered = new LinkedHashSet<>(applied.stream().map(Hook::className).toList());
        List<String> missing = devices.stream().filter(d -> !registered.contains(d)).toList();
        if (!missing.isEmpty()) {
            notes.add("인증 장치 " + missing + "의 등록(addInterceptor·<mvc:interceptor>·<filter-mapping>)을 이 저장소에서 찾지 못했습니다.");
        }
        if (applied.isEmpty()) {
            notes.add("등록된 인증 장치가 없어 엔드포인트별 인증 판정을 하지 않았습니다.");
            return new Result(false, List.of(), 0, notes);
        }
        List<Hook> unknown = applied.stream().filter(h -> !h.patternsKnown()).toList();
        if (!unknown.isEmpty()) {
            notes.add("인증 장치의 적용 경로를 상수로 읽지 못해(" + unknown.stream().map(Hook::registration).toList()
                    + ") 엔드포인트별 인증 판정을 하지 않았습니다. 경로를 문자열 상수로 쓰면 판정합니다.");
            return new Result(false, List.of(), 0, notes);
        }
        List<Endpoint> endpoints = endpoints(java, notes);
        List<Unprotected> unprotected = new ArrayList<>();
        for (Endpoint e : endpoints) {
            List<String> reasons = new ArrayList<>();
            for (String path : e.paths()) {
                if (applied.stream().anyMatch(h -> h.covers(path))) continue;
                reasons.add(path + " — " + why(applied, path));
            }
            if (!reasons.isEmpty()) unprotected.add(new Unprotected(e, reasons));
        }
        return new Result(true, unprotected, endpoints.size(), notes);
    }

    private static String why(List<Hook> hooks, String path) {
        List<String> parts = new ArrayList<>();
        for (Hook h : hooks) {
            Optional<String> excluded = h.exclude().stream().filter(p -> matches(h.kind(), p, path)).findFirst();
            if (excluded.isPresent() && h.include().stream().anyMatch(p -> matches(h.kind(), p, path))) {
                parts.add(h.className() + " 제외 경로 " + excluded.get() + " (" + h.registration() + ")");
            } else {
                parts.add(h.className() + " 적용 경로 " + h.include() + " 밖");
            }
        }
        return String.join("; ", parts);
    }

    /** 요청 처리 메서드 — 클래스의 @RequestMapping 경로 × 메서드의 매핑 경로. 경로를 상수로 못 읽은 메서드는 빼고 그 수를 알린다. */
    public static List<Endpoint> endpoints(JavaSourceIndex java, List<String> notes) {
        List<Endpoint> result = new ArrayList<>();
        int unresolved = 0;
        for (ClassOrInterfaceDeclaration type : sorted(java.allClasses())) {
            List<String> prefixes = List.of("");
            Optional<AnnotationExpr> classMapping = type.getAnnotationByName("RequestMapping");
            if (classMapping.isPresent()) {
                List<String> values = new ArrayList<>();
                if (!annotationStrings(classMapping.get(), Set.of("value", "path"), java, values)) {
                    unresolved += (int) type.getMethods().stream().filter(m -> mapping(m) != null).count();
                    continue;
                }
                if (!values.isEmpty()) prefixes = values;
            }
            for (MethodDeclaration method : type.getMethods()) {
                AnnotationExpr mapping = mapping(method);
                if (mapping == null) continue;
                List<String> values = new ArrayList<>();
                if (!annotationStrings(mapping, Set.of("value", "path"), java, values)) {
                    unresolved++;
                    continue;
                }
                if (values.isEmpty()) values = List.of("");
                List<String> paths = new ArrayList<>();
                for (String prefix : prefixes) for (String value : values) paths.add(join(prefix, value));
                String path = java.pathOf(method);
                if (path == null) continue;
                result.add(new Endpoint(path, mapping.getBegin().map(p -> p.line).orElse(0), httpMethod(mapping),
                        paths.stream().distinct().toList(), type.getNameAsString() + "." + method.getNameAsString() + "()"));
            }
        }
        if (unresolved > 0) {
            notes.add("요청 매핑 경로를 상수로 읽지 못한 메서드 " + unresolved + "개는 인증 판정에서 뺐습니다.");
        }
        return result;
    }

    private static AnnotationExpr mapping(MethodDeclaration method) {
        for (AnnotationExpr a : method.getAnnotations()) {
            if (MAPPING_METHODS.containsKey(a.getNameAsString())) return a;
        }
        return null;
    }

    private static String httpMethod(AnnotationExpr mapping) {
        String fixed = MAPPING_METHODS.get(mapping.getNameAsString());
        if (!fixed.equals("ALL") || !(mapping instanceof NormalAnnotationExpr normal)) return fixed;
        for (MemberValuePair pair : normal.getPairs()) {
            if (!pair.getNameAsString().equals("method")) continue;
            List<String> names = new ArrayList<>();
            Expression v = pair.getValue();
            List<Expression> items = v instanceof ArrayInitializerExpr array ? array.getValues() : List.of(v);
            for (Expression item : items) {
                String text = item.toString();
                names.add(text.substring(text.lastIndexOf('.') + 1));
            }
            return String.join(",", names);
        }
        return fixed;
    }

    // ================================================================ 탐지

    /** 판정 결과를 탐지로 — 위치는 요청 매핑 어노테이션 줄. 코드 조각·지문은 Semgrep 탐지와 같은 방법(SecureCodeSnippetBuilder)으로 만든다. */
    public static List<DetectedFinding> findings(Result result, SecureCodeSnippetBuilder snippetBuilder) throws IOException {
        List<SemgrepMatch> matches = new ArrayList<>();
        for (Unprotected u : result.unprotected()) {
            Endpoint e = u.endpoint();
            String message = e.httpMethod() + " " + String.join(", ", e.paths()) + " (" + e.handler() + ")에 인증 장치가 적용되지 않습니다. "
                    + "로그인 없이 호출해도 되는 기능(로그인·공개 화면)이 아니면 인증 장치의 적용 경로에 넣으세요. 이유: "
                    + String.join(" / ", u.reasons());
            // 탐지 메시지 컬럼 길이(1000) 안으로 — 경로가 많은 메서드는 이유가 길어진다.
            if (message.length() > MAX_MESSAGE_LENGTH) message = message.substring(0, MAX_MESSAGE_LENGTH - 1) + "…";
            matches.add(new SemgrepMatch(RULE_ID, KISA_CATEGORY, KISA_NAME, CWE, SEVERITY, e.filePath(), e.line(), e.line(), message));
        }
        return snippetBuilder.build(matches);
    }

    // ================================================================ 경로 패턴

    static boolean matches(Kind kind, String pattern, String path) {
        if (kind == Kind.INTERCEPTOR) return ANT.match(pattern, path);
        // 서블릿 url-pattern: /* 전체, /x/* 접두, *.ext 확장자, 그 밖은 정확히 같을 때
        if (pattern.equals("/*") || pattern.equals("/")) return true;
        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }
        if (pattern.startsWith("*.")) return path.endsWith(pattern.substring(1));
        return pattern.equals(path);
    }

    private static String join(String prefix, String value) {
        String joined = ("/" + prefix + "/" + value).replaceAll("/+", "/");
        return joined.length() > 1 && joined.endsWith("/") ? joined.substring(0, joined.length() - 1) : joined;
    }

    // ================================================================ 상수 읽기

    /** 어노테이션의 이름 있는 값(value·path 등)이나 하나뿐인 값을 문자열들로. 상수로 못 읽으면 false. */
    private static boolean annotationStrings(AnnotationExpr a, Set<String> names, JavaSourceIndex java, List<String> out) {
        if (a instanceof SingleMemberAnnotationExpr single) return strings(single.getMemberValue(), java, out, 0);
        if (a instanceof NormalAnnotationExpr normal) {
            boolean known = true;
            for (MemberValuePair pair : normal.getPairs()) {
                if (names.contains(pair.getNameAsString())) known &= strings(pair.getValue(), java, out, 0);
            }
            return known;
        }
        return true;
    }

    /** 문자열 상수·배열·List.of·Arrays.asList·상수 필드·문자열 연결을 문자열들로. 못 읽으면 false. */
    static boolean strings(Expression e, JavaSourceIndex java, List<String> out, int depth) {
        if (depth > MAX_CONSTANT_DEPTH) return false;
        if (e instanceof StringLiteralExpr s) {
            out.add(s.getValue());
            return true;
        }
        if (e instanceof ArrayInitializerExpr array) {
            boolean known = true;
            for (Expression v : array.getValues()) known &= strings(v, java, out, depth + 1);
            return known;
        }
        if (e instanceof ArrayCreationExpr creation) {
            return creation.getInitializer().map(i -> strings(i, java, out, depth + 1)).orElse(false);
        }
        if (e instanceof MethodCallExpr call && Set.of("asList", "of", "newArrayList").contains(call.getNameAsString())) {
            boolean known = true;
            for (Expression v : call.getArguments()) known &= strings(v, java, out, depth + 1);
            return known;
        }
        if (e instanceof BinaryExpr bin && bin.getOperator() == BinaryExpr.Operator.PLUS) {
            List<String> left = new ArrayList<>(), right = new ArrayList<>();
            if (strings(bin.getLeft(), java, left, depth + 1) && strings(bin.getRight(), java, right, depth + 1)
                    && left.size() == 1 && right.size() == 1) {
                out.add(left.get(0) + right.get(0));
                return true;
            }
            return false;
        }
        String name = e instanceof NameExpr n ? n.getNameAsString() : e instanceof FieldAccessExpr f ? f.getNameAsString() : null;
        if (name == null) return false;
        Optional<VariableDeclarator> field = constantField(e, name, java);
        return field.flatMap(VariableDeclarator::getInitializer).map(init -> strings(init, java, out, depth + 1)).orElse(false);
    }

    /** 이름이 같은 상수 필드 — 같은 클래스를 먼저, 없으면 저장소 전체에서 하나뿐일 때. */
    private static Optional<VariableDeclarator> constantField(Expression at, String name, JavaSourceIndex java) {
        Optional<ClassOrInterfaceDeclaration> own = at.findAncestor(ClassOrInterfaceDeclaration.class);
        if (own.isPresent()) {
            Optional<VariableDeclarator> local = fieldIn(own.get(), name);
            if (local.isPresent()) return local;
        }
        List<VariableDeclarator> all = java.allClasses().stream().map(c -> fieldIn(c, name)).flatMap(Optional::stream).toList();
        return all.size() == 1 ? Optional.of(all.get(0)) : Optional.empty();
    }

    private static Optional<VariableDeclarator> fieldIn(ClassOrInterfaceDeclaration type, String name) {
        for (FieldDeclaration field : type.getFields()) {
            if (!field.isFinal() && !type.isInterface()) continue;
            for (VariableDeclarator v : field.getVariables()) {
                if (v.getNameAsString().equals(name) && v.getInitializer().isPresent()) return Optional.of(v);
            }
        }
        return Optional.empty();
    }

    // ================================================================ 도움

    private static List<ClassOrInterfaceDeclaration> sorted(List<ClassOrInterfaceDeclaration> classes) {
        List<ClassOrInterfaceDeclaration> copy = new ArrayList<>(classes);
        copy.sort(Comparator.comparing(c -> c.getFullyQualifiedName().orElse(c.getNameAsString())));
        return copy;
    }

    private static List<String> all(Pattern pattern, String text) {
        List<String> values = new ArrayList<>();
        Matcher m = pattern.matcher(text);
        while (m.find()) values.add(m.group(1).strip());
        return values;
    }

    private static String stripComments(String xml) {
        // 같은 길이의 공백으로 — 줄 번호·위치를 유지한다.
        StringBuilder masked = new StringBuilder(xml);
        Matcher comment = XML_COMMENT.matcher(xml);
        while (comment.find()) {
            for (int i = comment.start(); i < comment.end(); i++) {
                if (masked.charAt(i) != '\n') masked.setCharAt(i, ' ');
            }
        }
        return masked.toString();
    }

    private static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < text.length(); i++) if (text.charAt(i) == '\n') line++;
        return line;
    }

    private static String simpleClass(String fqcn) {
        String name = fqcn.strip();
        return name.substring(name.lastIndexOf('.') + 1);
    }

    private static String fileName(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    private static String abbreviate(String code) {
        String line = code.replaceAll("\\s+", " ").strip();
        return line.length() > 160 ? line.substring(0, 157) + "..." : line;
    }
}
