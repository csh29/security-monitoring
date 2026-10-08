package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.FrameworkFact;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex;

/**
 * 점검 대상 저장소의 설정 파일(빌드 파일·web.xml·Spring XML·application.yml/properties·MyBatis/iBatis 설정)과 Java 소스를 읽어
 * 프레임워크 구조(웹·영속성·AOP·인터셉터·필터·세션 저장소)를 근거와 함께 정리한다. 결정론이고 소스는 서버 밖으로 나가지 않는다.
 *
 * <p>두 가지에 쓴다.
 * <ul>
 *   <li><b>구조 기록</b>({@link #profile}) — trace-rules.yml의 frameworks에 시스템별로 남긴다. 판정에는 쓰지 않는다. 사람이 추적 규칙 초안
 *       ("이 어노테이션이 세션 값을 넣는다")을 받아들일지 판단할 때 그 시스템이 어떤 방식으로 요청을 받고 로그인 정보를 다루는지 보는 근거다.</li>
 *   <li><b>XML로 설정한 AOP</b>({@link #xmlAdvices}) — {@code <aop:config>}의 before·around 어드바이스. 어노테이션({@code @Aspect})으로 쓴 AOP만
 *       보던 TraceRuleDrafter가 이것도 세션 덮어쓰기 후보로 만든다(옛 Spring XML 시스템은 대부분 이 방식이다).</li>
 * </ul>
 *
 * <p>설정 값은 기록하지 않는다 — 비밀번호·접속 주소가 섞여 있어서, 정해 둔 키(세션 저장소 종류 등)만 값을 읽고 나머지는 키 이름까지만 본다.
 */
public final class FrameworkProfiler {

    /** 구조 기록의 구분. label이 trace-rules.yml frameworks의 kind 값이다. */
    public enum Kind {
        WEB("웹"), PERSISTENCE("영속성"), AOP("AOP"), INTERCEPTOR("인터셉터"), FILTER("필터"), SESSION("세션"), CONFIG("설정 파일");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** 빌드 파일에서 찾는 의존성(아티팩트 이름에 들어가는 문자열). */
    private record Dependency(String token, Kind kind, String name) {
    }

    /**
     * XML로 설정한 AOP 어드바이스 하나.
     *
     * @param aspectClass 어드바이스 메서드가 있는 클래스의 단순 이름(bean의 class 또는 컴포넌트 이름으로 찾은 것). 못 찾으면 bean id
     * @param method      어드바이스 메서드 이름
     * @param pointcut    포인트컷 식(pointcut-ref면 그 aop:pointcut의 식으로 바꾼 것)
     * @param evidence    "파일:줄 <aop:before …>"
     */
    public record XmlAdvice(String aspectClass, String method, String pointcut, String evidence) {
    }

    private static final Pattern TAG = Pattern.compile("<([\\w:.-]+)((?:\\s+[\\w:.-]+\\s*=\\s*(?:\"[^\"]*\"|'[^']*'))*)\\s*/?>");
    private static final Pattern ATTR = Pattern.compile("([\\w:.-]+)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')");
    private static final Pattern XML_COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);
    private static final Set<String> ADVICE_TAGS = Set.of("aop:before", "aop:around");
    private static final List<Dependency> DEPENDENCIES = List.of(
            new Dependency("spring-boot-starter-web", Kind.WEB, "Spring Boot MVC"),
            new Dependency("spring-boot-starter-webflux", Kind.WEB, "Spring WebFlux"),
            new Dependency("spring-webmvc", Kind.WEB, "Spring MVC"),
            new Dependency("struts2-core", Kind.WEB, "Struts 2"),
            new Dependency("struts-core", Kind.WEB, "Struts 1"),
            new Dependency("egovframework.rte", Kind.WEB, "전자정부 표준프레임워크"),
            new Dependency("mybatis-spring-boot-starter", Kind.PERSISTENCE, "MyBatis(Spring Boot)"),
            new Dependency("mybatis-spring", Kind.PERSISTENCE, "MyBatis(Spring)"),
            new Dependency("ibatis-sqlmap", Kind.PERSISTENCE, "iBatis 2"),
            new Dependency("spring-boot-starter-data-jpa", Kind.PERSISTENCE, "JPA(Spring Data)"),
            new Dependency("hibernate-core", Kind.PERSISTENCE, "Hibernate"),
            new Dependency("spring-boot-starter-aop", Kind.AOP, "Spring AOP(Spring Boot)"),
            new Dependency("aspectjweaver", Kind.AOP, "AspectJ"),
            new Dependency("spring-session-data-redis", Kind.SESSION, "Spring Session(Redis)"),
            new Dependency("spring-session-jdbc", Kind.SESSION, "Spring Session(JDBC)"),
            new Dependency("spring-boot-starter-security", Kind.FILTER, "Spring Security"),
            new Dependency("spring-security-web", Kind.FILTER, "Spring Security"));
    private static final Pattern BOOT_PARENT = Pattern.compile(
            "<parent>.*?<artifactId>\\s*spring-boot-starter-parent\\s*</artifactId>\\s*<version>\\s*([^<\\s]+)\\s*</version>", Pattern.DOTALL);
    private static final Pattern BOOT_GRADLE = Pattern.compile("org\\.springframework\\.boot['\"]?\\)?\\s*version\\s*['\"]([^'\"]+)['\"]");
    /** 값을 읽어도 되는 설정 키(비밀값이 아닌 종류 이름). 나머지는 키 이름만 본다. */
    private static final Map<String, String> VALUE_KEYS = Map.of(
            "spring.session.store-type", "세션 저장소",
            "server.servlet.session.timeout", "세션 만료",
            "spring.aop.proxy-target-class", "AOP 프록시 방식");

    private FrameworkProfiler() {
    }

    /**
     * 구조 기록. 같은 (구분, 값)은 처음 찾은 근거 하나만 남기고, 근거에 줄 번호를 넣지 않는다 — 구조가 그대로면 점검마다 같은 결과여야
     * trace-rules.yml이 코드 몇 줄 바뀐 것으로 다시 쓰이지 않는다.
     *
     * @param sources 저장소 루트 기준 경로 → 내용(MybatisDollarTracer.readSources — .java·.xml·설정 파일)
     */
    public static List<FrameworkFact> profile(Map<String, String> sources, JavaSourceIndex java) {
        Map<String, FrameworkFact> facts = new LinkedHashMap<>();
        // 경로 순서대로(TreeMap) 돌아 같은 저장소면 같은 순서·같은 근거가 나온다.
        sources.forEach((path, content) -> {
            String name = fileName(path);
            if (name.equals("pom.xml")) buildFile(path, content, BOOT_PARENT, facts);
            else if (name.equals("build.gradle") || name.equals("build.gradle.kts")) buildFile(path, content, BOOT_GRADLE, facts);
            else if (name.equals("web.xml")) webXml(path, content, facts);
            else if (name.equals("struts.xml") || name.equals("struts-config.xml")) add(facts, Kind.WEB, name.startsWith("struts-config") ? "Struts 1" : "Struts 2", path);
            else if (name.endsWith(".xml") && content.contains("<beans")) springXml(path, content, facts);
            else if (name.endsWith(".xml") && content.contains("<sqlMapConfig")) add(facts, Kind.PERSISTENCE, "iBatis 2", path + " <sqlMapConfig>");
            else if (name.endsWith(".xml") && content.contains("<configuration") && content.contains("mybatis")) add(facts, Kind.PERSISTENCE, "MyBatis", path + " <configuration>");
            else if (isAppConfig(name)) appConfig(path, content, facts);
        });
        javaFacts(java, facts);
        return new ArrayList<>(facts.values());
    }

    /** {@code <aop:config>} 안의 before·around 어드바이스. 우리 소스의 클래스로 이어 줄 수 있게 bean id를 클래스 이름으로 바꾼다. */
    public static List<XmlAdvice> xmlAdvices(Map<String, String> sources) {
        Map<String, String> beanClasses = new LinkedHashMap<>();
        sources.forEach((path, content) -> {
            if (!path.endsWith(".xml") || !content.contains("<bean")) return;
            for (Tag tag : tags(content)) {
                if (tag.name().equals("bean") && tag.attr("id") != null && tag.attr("class") != null) {
                    beanClasses.putIfAbsent(tag.attr("id"), simpleClass(tag.attr("class")));
                }
            }
        });
        List<XmlAdvice> advices = new ArrayList<>();
        sources.forEach((path, content) -> {
            if (!path.endsWith(".xml") || !content.contains("<aop:config")) return;
            Map<String, String> pointcuts = new LinkedHashMap<>();
            List<Tag> tags = tags(content);
            for (Tag tag : tags) {
                if (tag.name().equals("aop:pointcut") && tag.attr("id") != null && tag.attr("expression") != null) {
                    pointcuts.put(tag.attr("id"), tag.attr("expression"));
                }
            }
            String aspectRef = null;
            for (Tag tag : tags) {
                if (tag.name().equals("aop:aspect")) {
                    aspectRef = tag.attr("ref");
                } else if (ADVICE_TAGS.contains(tag.name()) && aspectRef != null && tag.attr("method") != null) {
                    String pointcut = tag.attr("pointcut") != null ? tag.attr("pointcut") : pointcuts.get(tag.attr("pointcut-ref"));
                    if (pointcut == null) continue;
                    String aspectClass = beanClasses.getOrDefault(aspectRef, componentClass(aspectRef));
                    advices.add(new XmlAdvice(aspectClass, tag.attr("method"), pointcut,
                            fileName(path) + ":" + tag.line() + " <" + tag.name() + " method=\"" + tag.attr("method") + "\" pointcut=\"" + pointcut + "\">"));
                }
            }
        });
        return advices;
    }

    // ---------------------------------------------------------------- 파일별

    private static void buildFile(String path, String content, Pattern bootVersion, Map<String, FrameworkFact> facts) {
        Matcher boot = bootVersion.matcher(content);
        if (boot.find()) add(facts, Kind.WEB, "Spring Boot " + boot.group(1), fileName(path) + " spring-boot " + boot.group(1));
        for (Dependency dep : DEPENDENCIES) {
            // 이름 전체가 맞을 때만 — "mybatis-spring"이 "mybatis-spring-boot-starter" 안에서 또 걸리지 않게(pom의 >이름<, gradle의 :이름:).
            if (Pattern.compile("(?<=[>:'\"])" + Pattern.quote(dep.token()) + "(?=[<:'\".])").matcher(content).find()) {
                add(facts, dep.kind(), dep.name(), fileName(path) + " " + dep.token());
            }
        }
    }

    private static void webXml(String path, String content, Map<String, FrameworkFact> facts) {
        for (Tag tag : tags(content)) {
            if (!tag.name().equals("servlet-class") && !tag.name().equals("filter-class") && !tag.name().equals("listener-class")) continue;
            String value = textAfter(content, tag);
            if (value.isEmpty()) continue;
            String evidence = fileName(path) + " <" + tag.name() + ">" + value;
            if (tag.name().equals("filter-class")) add(facts, Kind.FILTER, simpleClass(value), evidence);
            else if (value.endsWith("DispatcherServlet")) add(facts, Kind.WEB, "Spring MVC(web.xml DispatcherServlet)", evidence);
            else if (value.contains("struts")) add(facts, Kind.WEB, value.contains("struts2") ? "Struts 2" : "Struts 1", evidence);
        }
        if (content.contains("<session-config")) add(facts, Kind.SESSION, "web.xml session-config", fileName(path) + " <session-config>");
    }

    private static void springXml(String path, String content, Map<String, FrameworkFact> facts) {
        String file = fileName(path);
        for (Tag tag : tags(content)) {
            switch (tag.name()) {
                case "aop:config" -> add(facts, Kind.AOP, "XML AOP(<aop:config>)", file + " <aop:config>");
                case "aop:aspectj-autoproxy" -> add(facts, Kind.AOP, "어노테이션 AOP(<aop:aspectj-autoproxy>)", file + " <aop:aspectj-autoproxy>");
                case "mvc:annotation-driven" -> add(facts, Kind.WEB, "Spring MVC(XML 설정)", file + " <mvc:annotation-driven>");
                case "aop:aspect" -> {
                    if (tag.attr("ref") != null) add(facts, Kind.AOP, "XML 애스펙트 " + tag.attr("ref"), file + " <aop:aspect ref=\"" + tag.attr("ref") + "\">");
                }
                case "bean" -> {
                    String cls = tag.attr("class");
                    if (cls == null) break;
                    if (cls.contains("SqlSessionFactoryBean")) add(facts, Kind.PERSISTENCE, "MyBatis(Spring)", file + " " + simpleClass(cls));
                    else if (cls.contains("SqlMapClientFactoryBean")) add(facts, Kind.PERSISTENCE, "iBatis 2", file + " " + simpleClass(cls));
                    else if (insideInterceptors(content, tag)) add(facts, Kind.INTERCEPTOR, simpleClass(cls), file + " <mvc:interceptors> " + cls);
                }
                default -> {
                }
            }
        }
    }

    private static void appConfig(String path, String content, Map<String, FrameworkFact> facts) {
        String file = fileName(path);
        add(facts, Kind.CONFIG, file, path);
        // yml은 들여쓰기 키라 "a.b" 모양으로 바로 찾을 수 없다 — 마지막 키 이름과 줄로 찾는다. 값은 VALUE_KEYS만 읽는다.
        String[] lines = content.split("\\R", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].strip();
            if (line.startsWith("#")) continue;
            if (line.startsWith("mybatis.") || line.startsWith("mybatis:")) {
                add(facts, Kind.PERSISTENCE, "MyBatis(Spring Boot)", file + " mybatis 설정");
            }
            for (Map.Entry<String, String> key : VALUE_KEYS.entrySet()) {
                String last = key.getKey().substring(key.getKey().lastIndexOf('.') + 1);
                String value = valueOf(line, key.getKey(), last, file);
                if (value != null) add(facts, Kind.SESSION, key.getValue() + " " + value, file + " " + key.getKey());
            }
        }
    }

    /** 우리 소스에서 직접 만든 장치: 인터셉터·필터·요청 래퍼·@Aspect, Java 설정으로 등록한 것. */
    private static void javaFacts(JavaSourceIndex java, Map<String, FrameworkFact> facts) {
        // 클래스 이름 순으로 — 색인의 HashMap 순서를 그대로 쓰면 같은 저장소라도 기록 순서가 실행마다 달라진다.
        List<ClassOrInterfaceDeclaration> classes = new ArrayList<>(java.allClasses());
        classes.sort(Comparator.comparing(c -> c.getFullyQualifiedName().orElse(c.getNameAsString())));
        for (ClassOrInterfaceDeclaration type : classes) {
            String name = type.getNameAsString();
            String at = fileOf(java.location(type)) + " " + name;
            if (JavaSourceIndex.hasAnnotation(type, "SpringBootApplication")) add(facts, Kind.WEB, "Spring Boot", at + " @SpringBootApplication");
            if (JavaSourceIndex.hasAnnotation(type, "Aspect")) add(facts, Kind.AOP, "@Aspect " + name, at);
            if (JavaSourceIndex.hasAnnotation(type, "EnableAspectJAutoProxy")) add(facts, Kind.AOP, "어노테이션 AOP(@EnableAspectJAutoProxy)", at);
            if (inherits(type, Set.of("HandlerInterceptor", "HandlerInterceptorAdapter", "AsyncHandlerInterceptor"))) add(facts, Kind.INTERCEPTOR, name, at);
            if (inherits(type, Set.of("Filter", "OncePerRequestFilter", "GenericFilterBean"))) add(facts, Kind.FILTER, name, at);
            if (inherits(type, Set.of("HttpServletRequestWrapper"))) add(facts, Kind.FILTER, "요청 래퍼 " + name, at + " — 요청 파라미터를 바꿀 수 있다");
            for (MethodDeclaration method : type.getMethodsByName("addInterceptors")) {
                for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {
                    if (!call.getNameAsString().equals("addInterceptor") || call.getArguments().isEmpty()) continue;
                    String target = call.getArgument(0) instanceof ObjectCreationExpr created
                            ? created.getType().getNameAsString() : call.getArgument(0).toString();
                    add(facts, Kind.INTERCEPTOR, target, fileOf(java.location(call)) + " addInterceptor(" + target + ")");
                }
            }
        }
    }

    // ---------------------------------------------------------------- 도움

    /** 값·근거는 한 줄로 — trace-rules.yml에 한 줄씩 쓰고, 다시 읽었을 때 같은 값이어야 한다(TraceRulesFileEditor의 검증). */
    private static void add(Map<String, FrameworkFact> facts, Kind kind, String value, String evidence) {
        String v = oneLine(value);
        facts.putIfAbsent(kind.label() + "|" + v, new FrameworkFact(kind.label(), v, oneLine(evidence)));
    }

    private static String oneLine(String text) {
        String line = text.replaceAll("\\s+", " ").strip();
        return line.length() > 200 ? line.substring(0, 197) + "..." : line;
    }

    private static boolean inherits(ClassOrInterfaceDeclaration type, Set<String> bases) {
        return type.getExtendedTypes().stream().anyMatch(t -> bases.contains(t.getNameAsString()))
                || type.getImplementedTypes().stream().anyMatch(t -> bases.contains(t.getNameAsString()));
    }

    /**
     * 구조를 읽으려고 .java·.xml 말고 더 읽는 설정 파일(MybatisDollarTracer.readSources). 저장소의 모든 yml·properties를 읽지 않는다 —
     * 메시지 번들 등 수백 개가 있을 수 있다.
     */
    public static boolean isConfigFile(String path) {
        String name = fileName(path);
        return name.equals("build.gradle") || name.equals("build.gradle.kts") || isAppConfig(name);
    }

    private static boolean isAppConfig(String name) {
        return (name.startsWith("application") || name.startsWith("bootstrap"))
                && (name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".properties"));
    }

    /** properties("a.b.c=v") 또는 yml("c: v")에서 정해 둔 키의 값. yml은 마지막 키 이름만 보고 판단한다(들여쓰기 경로까지는 보지 않는다). */
    private static String valueOf(String line, String fullKey, String lastKey, String file) {
        String value = null;
        if (file.endsWith(".properties") && (line.startsWith(fullKey + "=") || line.startsWith(fullKey + ":"))) {
            value = line.substring(fullKey.length() + 1);
        } else if (!file.endsWith(".properties") && line.startsWith(lastKey + ":")) {
            value = line.substring(lastKey.length() + 1);
        }
        if (value == null) return null;
        value = value.replaceAll("\\s+#.*$", "").strip().replaceAll("^[\"']|[\"']$", "");
        // ${...} 참조·빈 값은 실제 값을 모른다.
        return value.isEmpty() || value.contains("${") ? null : value;
    }

    private static boolean insideInterceptors(String content, Tag tag) {
        int open = content.lastIndexOf("<mvc:interceptors", tag.offset());
        int close = content.lastIndexOf("</mvc:interceptors", tag.offset());
        return open >= 0 && open > close;
    }

    private static String textAfter(String content, Tag tag) {
        int end = content.indexOf('<', tag.end());
        return end < 0 ? "" : content.substring(tag.end(), end).strip();
    }

    /** "com.x.UserInfoAspect" → "UserInfoAspect". */
    static String simpleClass(String fqcn) {
        String name = fqcn.strip();
        return name.substring(name.lastIndexOf('.') + 1);
    }

    /** 컴포넌트 스캔 빈 이름("userInfoAspect")은 클래스 이름의 첫 글자를 소문자로 바꾼 것이다. */
    private static String componentClass(String beanName) {
        return beanName.isEmpty() ? beanName : Character.toUpperCase(beanName.charAt(0)) + beanName.substring(1);
    }

    private static String fileName(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /** "Crc020Service.java:102" → "Crc020Service.java". */
    private static String fileOf(String location) {
        return location.replaceFirst(":\\d+$", "");
    }

    /** XML 시작 태그 하나(주석 안은 뺀다). offset·end는 원문 기준. */
    private record Tag(String name, Map<String, String> attrs, int offset, int end, int line) {
        String attr(String key) {
            return attrs.get(key);
        }
    }

    private static List<Tag> tags(String content) {
        // 주석은 같은 길이의 공백으로 바꿔 줄 번호·위치를 유지한다.
        StringBuilder masked = new StringBuilder(content);
        Matcher comment = XML_COMMENT.matcher(content);
        while (comment.find()) {
            for (int i = comment.start(); i < comment.end(); i++) {
                if (masked.charAt(i) != '\n') masked.setCharAt(i, ' ');
            }
        }
        List<Tag> tags = new ArrayList<>();
        Matcher m = TAG.matcher(masked);
        // 태그는 앞에서부터 나오므로 줄 번호를 이어서 센다(태그마다 처음부터 세면 큰 설정 파일에서 제곱으로 느려진다).
        int line = 1;
        int counted = 0;
        while (m.find()) {
            for (; counted < m.start(); counted++) {
                if (content.charAt(counted) == '\n') line++;
            }
            Map<String, String> attrs = new LinkedHashMap<>();
            Matcher a = ATTR.matcher(m.group(2));
            while (a.find()) attrs.put(a.group(1), unescape(a.group(2) != null ? a.group(2) : a.group(3)));
            tags.add(new Tag(m.group(1), attrs, m.start(), m.end(), line));
        }
        return tags;
    }

    private static String unescape(String value) {
        return value.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'");
    }
}
