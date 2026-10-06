package com.sjinc.cvemonitor.service.securecode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MyBatis 매퍼 XML에서 {@code ${}} 사용 위치와, 그 값을 XML 안에서 이미 정해 버리는 장치(bind·조건 검사)를 뽑는다.
 *
 * <p>DOM 파서를 쓰지 않고 태그를 직접 훑는다 — Semgrep 탐지와 맞추려면 {@code ${}}마다 정확한 줄 번호가 필요한데 DOM은
 * 줄 번호를 주지 않고, 매퍼 XML은 DOCTYPE(외부 DTD)을 달고 있어 파서가 DTD를 내려받으려 한다. 매퍼 XML은 구조가 단순해
 * (태그·주석·CDATA·속성뿐) 이 정도로 충분하다. 주석 안의 {@code ${}}는 MyBatis가 실행하지 않으니 Semgrep 규칙처럼 뺀다.
 */
final class MapperXmlIndex {

    /** XML 하나의 결과. 매퍼가 아닌 XML(pom.xml 등)이면 만들지 않는다. */
    record MapperFile(String path, String namespace, List<Statement> statements, List<Fragment> fragments) {
    }

    /** select/insert/update/delete 하나. includes는 이 구문이 끌어다 쓰는 sql 조각 id(namespace 붙은 전체 id). */
    record Statement(String fullId, List<Dollar> dollars, Set<String> includes) {
    }

    /** {@code <sql id>} 조각. 조각 안의 {@code ${}}는 그 조각을 include한 구문마다 따로 판정한다. */
    record Fragment(String fullId, List<Dollar> dollars, Set<String> includes) {
    }

    /**
     * {@code ${expr}} 한 개.
     *
     * @param key        값을 꺼내는 파라미터 키(expr의 첫 이름. {@code ym.substring(2)} → ym). foreach 항목이면 컬렉션 키로 바꾼 값
     * @param xmlFixed   XML 안에서 값이 정해져 호출 쪽과 무관하게 안전하면 그 근거, 아니면 null
     * @param bindFrom   {@code <bind>}가 이 키를 다른 키들로 다시 만든 경우 그 원래 키들(호출 쪽에서는 이 키들을 따라간다). 없으면 빈 집합
     */
    record Dollar(String path, int line, String expr, String key, String xmlFixed, Set<String> bindFrom) {
    }

    private static final Pattern TOKEN = Pattern.compile(
            "<!--.*?-->"                                  // 주석
                    + "|<!\\[CDATA\\[(.*?)]]>"            // CDATA — 안은 실행되는 SQL 텍스트다
                    + "|<[!?][^>]*>"                       // DOCTYPE, <?xml ?>
                    // 태그. test="cnt > 0"처럼 속성 값 안에 >가 올 수 있어 따옴표 묶음을 통째로 넘긴다.
                    + "|<(/?)([\\w.:-]+)((?:\\s+[\\w.:-]+\\s*=\\s*(?:\"[^\"]*\"|'[^']*'))*)\\s*(/?)>",
            Pattern.DOTALL);
    private static final Pattern ATTR = Pattern.compile("([\\w.:-]+)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')");
    private static final Pattern DOLLAR = Pattern.compile("\\$\\{([^}]+)}");
    private static final Pattern FIRST_NAME = Pattern.compile("^\\s*([A-Za-z_$][\\w$]*)");
    private static final Set<String> STATEMENT_TAGS = Set.of("select", "insert", "update", "delete");
    /** OGNL에서 이름처럼 보이지만 파라미터 키가 아닌 것. */
    private static final Set<String> OGNL_WORDS = Set.of("and", "or", "not", "null", "true", "false",
            "eq", "neq", "lt", "gt", "lte", "gte", "in", "instanceof", "new", "_databaseId");

    private MapperXmlIndex() {
    }

    /** 매퍼 XML이 아니면 null. */
    static MapperFile parse(String path, String content) {
        Parser parser = new Parser(path, content);
        parser.run();
        if (parser.namespace == null) {
            return null;
        }
        return new MapperFile(path, parser.namespace, parser.statements, parser.fragments);
    }

    /** 열린 태그 하나. if/when은 test, foreach는 item·collection, bind는 name·value를 들고 있다. */
    private record Open(String tag, Map<String, String> attrs, List<Dollar> dollars, Set<String> includes,
                        Map<String, String> binds) {
    }

    private static final class Parser {
        private final String path;
        private final String content;
        private final int[] lineStarts;
        private String namespace;
        private final List<Statement> statements = new ArrayList<>();
        private final List<Fragment> fragments = new ArrayList<>();
        private final Deque<Open> stack = new ArrayDeque<>();

        Parser(String path, String content) {
            this.path = path;
            this.content = content;
            List<Integer> starts = new ArrayList<>();
            starts.add(0);
            for (int i = 0; i < content.length(); i++) {
                if (content.charAt(i) == '\n') starts.add(i + 1);
            }
            this.lineStarts = starts.stream().mapToInt(Integer::intValue).toArray();
        }

        void run() {
            Matcher m = TOKEN.matcher(content);
            int last = 0;
            while (m.find()) {
                text(last, m.start());
                last = m.end();
                String token = m.group();
                if (token.startsWith("<!--") || (token.startsWith("<!") && !token.startsWith("<![CDATA[")) || token.startsWith("<?")) {
                    continue;
                }
                if (token.startsWith("<![CDATA[")) {
                    text(m.start(1), m.end(1));
                    continue;
                }
                boolean closing = !m.group(2).isEmpty();
                String tag = m.group(3);
                boolean selfClosing = !m.group(5).isEmpty();
                if (closing) {
                    close(tag);
                } else {
                    open(tag, attrs(m.group(4)), selfClosing);
                }
            }
            text(last, content.length());
        }

        private void open(String tag, Map<String, String> attrs, boolean selfClosing) {
            if ("mapper".equals(tag)) {
                namespace = attrs.get("namespace");
            }
            Open statement = currentStatement();
            if (statement != null && "include".equals(tag) && attrs.get("refid") != null) {
                statement.includes().add(qualify(attrs.get("refid")));
            }
            if (statement != null && "bind".equals(tag) && attrs.get("name") != null) {
                statement.binds().put(attrs.get("name"), attrs.getOrDefault("value", ""));
            }
            if (selfClosing) {
                return;
            }
            boolean isStatement = namespace != null && attrs.get("id") != null
                    && (STATEMENT_TAGS.contains(tag) || "sql".equals(tag));
            stack.push(new Open(tag, attrs,
                    isStatement ? new ArrayList<>() : null,
                    isStatement ? new LinkedHashSet<>() : null,
                    isStatement ? new LinkedHashMap<>() : null));
        }

        private void close(String tag) {
            // 짝이 안 맞는 XML이라도 멈추지 않는다 — 같은 이름이 나올 때까지 닫는다.
            while (!stack.isEmpty()) {
                Open top = stack.pop();
                if (top.dollars() != null) {
                    String fullId = namespace + "." + top.attrs().get("id");
                    if ("sql".equals(top.tag())) {
                        fragments.add(new Fragment(fullId, top.dollars(), top.includes()));
                    } else {
                        statements.add(new Statement(fullId, top.dollars(), top.includes()));
                    }
                }
                if (top.tag().equals(tag)) {
                    return;
                }
            }
        }

        private void text(int from, int to) {
            Open statement = currentStatement();
            if (statement == null || from >= to) {
                return;
            }
            Matcher m = DOLLAR.matcher(content);
            m.region(from, to);
            while (m.find()) {
                String expr = m.group(1).trim();
                statement.dollars().add(dollar(expr, line(m.start()), statement));
            }
        }

        private Dollar dollar(String expr, int line, Open statement) {
            Matcher name = FIRST_NAME.matcher(expr);
            String key = name.find() ? name.group(1) : expr;
            // foreach 항목(${item})은 컬렉션의 한 원소다 — 값의 출처는 컬렉션 키와 같다.
            for (Open open : stack) {
                if ("foreach".equals(open.tag()) && key.equals(open.attrs().get("item"))
                        && open.attrs().get("collection") != null) {
                    Matcher collection = FIRST_NAME.matcher(open.attrs().get("collection"));
                    if (collection.find()) key = collection.group(1);
                    break;
                }
            }
            String xmlFixed = null;
            Set<String> bindFrom = Set.of();
            String bind = statement.binds().get(key);
            if (bind != null) {
                Set<String> names = ognlNames(bind);
                if (names.isEmpty()) {
                    xmlFixed = "<bind name=\"" + key + "\" value=\"" + bind + "\"> 상수로 덮어씀";
                } else {
                    bindFrom = names;
                }
            }
            if (xmlFixed == null) {
                xmlFixed = guard(key);
            }
            return new Dollar(path, line, expr, key, xmlFixed, bindFrom);
        }

        /**
         * 바깥 if/when의 test가 이 키를 상수 목록으로 묶어 두면({@code sortOrd == 'A' or sortOrd == 'B'}) 그 안의 ${key}는
         * 상수 중 하나일 때만 실행된다 — 허용 목록 검증이 XML에 있는 것이다.
         */
        private String guard(String key) {
            String quoted = Pattern.quote(key);
            Pattern equality = Pattern.compile("^\\s*(?:" + quoted + "\\s*(?:==|eq)\\s*('[^']*'|\"[^\"]*\")"
                    + "|('[^']*'|\"[^\"]*\")\\s*(?:==|eq)\\s*" + quoted + ")\\s*$");
            for (Open open : stack) {
                if (!"if".equals(open.tag()) && !"when".equals(open.tag())) continue;
                String test = unescape(open.attrs().getOrDefault("test", ""));
                for (String conjunct : test.split("\\s+and\\s+|&&")) {
                    String[] options = conjunct.trim().replaceAll("^\\((.*)\\)$", "$1").split("\\s+or\\s+|\\|\\|");
                    boolean allEqual = true;
                    for (String option : options) {
                        if (!equality.matcher(option).matches()) {
                            allEqual = false;
                            break;
                        }
                    }
                    if (allEqual) {
                        return "<" + open.tag() + " test=\"" + test + "\"> 상수 비교 안에서만 실행";
                    }
                }
            }
            return null;
        }

        private Open currentStatement() {
            for (Open open : stack) {
                if (open.dollars() != null) return open;
            }
            return null;
        }

        private String qualify(String refid) {
            return refid.contains(".") ? refid : namespace + "." + refid;
        }

        private int line(int offset) {
            int lo = 0, hi = lineStarts.length - 1;
            while (lo < hi) {
                int mid = (lo + hi + 1) >>> 1;
                if (lineStarts[mid] <= offset) lo = mid;
                else hi = mid - 1;
            }
            return lo + 1;
        }
    }

    /** OGNL 식에서 파라미터 키로 보이는 이름들. 문자열 상수·메서드 이름(.trim)·호출(fn())은 뺀다. */
    static Set<String> ognlNames(String ognl) {
        String withoutStrings = ognl.replaceAll("'[^']*'|\"[^\"]*\"", " ");
        Set<String> names = new LinkedHashSet<>();
        Matcher m = Pattern.compile("(?<![\\w.$@])([A-Za-z_$][\\w$]*)(?!\\s*\\()").matcher(withoutStrings);
        while (m.find()) {
            String name = m.group(1);
            if (!OGNL_WORDS.contains(name) && !name.matches("\\d.*")) names.add(name);
        }
        return names;
    }

    private static Map<String, String> attrs(String raw) {
        Map<String, String> attrs = new HashMap<>();
        Matcher m = ATTR.matcher(raw == null ? "" : raw);
        while (m.find()) {
            attrs.put(m.group(1), m.group(2) != null ? m.group(2) : m.group(3));
        }
        return attrs;
    }

    private static String unescape(String value) {
        return value.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
                .replace("&apos;", "'").replace("&amp;", "&");
    }
}
