package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.FrameworkFact;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * trace-rules.yml에 변경(TraceRuleChange)을 글자 단위로 적용한다. YAML을 읽어 통째로 다시 쓰지 않는 이유는 주석 때문이다 — 이 파일의 주석은
 * "왜 이 키는 빼 두었나"(regPgmId) 같은 판단 기록이라, 다시 쓰면서 지워지면 다음 사람이 같은 실수를 한다. 그래서 바꿀 줄만 고치고,
 * 고친 곳 위에 언제·누가·왜 고쳤는지 주석을 한 줄 단다.
 *
 * <p>고친 결과를 다시 읽어 "지금 규칙에 변경을 적용한 규칙"과 같은지 확인하고, 다르면 예외를 던진다(파일은 쓰지 않는다). 사람이 손으로 쓴
 * 파일 모양이 예상과 달라(키 목록을 여러 줄로 썼다 등) 엉뚱한 곳을 고치는 일을 막는다.
 *
 * <p>frameworks(프레임워크 구조)는 서버가 쓰는 기록이라 섹션을 통째로 다시 쓰고, 항상 파일 맨 끝에 둔다.
 */
public final class TraceRulesFileEditor {

    static final String FRAMEWORKS = "frameworks";
    private static final String INDENT = "  ";
    private static final Pattern FLOW_LIST = Pattern.compile("^(\\s*[\\w-]+:\\s*)\\[([^\\]]*)]\\s*(#.*)?$");
    private static final String FRAMEWORKS_HEADER = """
            # 프레임워크 구조 — 점검 때 서버가 시스템별로 설정 파일(빌드 파일·web.xml·Spring XML·application.yml 등)과 소스를 읽어 기록한다
            # (FrameworkProfiler). 판정에는 쓰지 않는다. 위 규칙의 확인 대기 초안을 반영할지 판단할 때 그 시스템이 어떤 구조인지 보는 근거다.
            # 구조가 바뀌면 다음 점검이 이 섹션을 다시 쓰므로 손으로 고치지 않는다.""";

    private TraceRulesFileEditor() {
    }

    /**
     * @param content 지금 파일 내용(파일이 없으면 빈 문자열)
     * @param stamp   고친 곳에 남길 표시(예: "2026-10-08 자동 반영", "2026-10-08 반영 admin")
     * @return 고친 내용
     * @throws IllegalStateException 고친 결과가 의도한 규칙과 다를 때(파일 모양이 예상과 다름)
     */
    public static String apply(String content, List<TraceRuleChange> changes, String stamp) {
        TraceRules expected = TraceRules.parse(content);
        List<String> lines = new ArrayList<>(Arrays.asList(normalize(content).split("\n", -1)));
        if (lines.size() == 1 && lines.get(0).isEmpty()) lines.clear();
        for (TraceRuleChange change : changes) {
            TraceRules before = expected;
            expected = change.applyTo(expected);
            if (expected.equals(before)) continue; // 이미 반영돼 있으면 주석도 달지 않는다.
            switch (change.type()) {
                // 그사이 같은 장치를 손으로 넣었으면 applyTo가 키만 합치므로 파일도 그 항목의 키만 고친다.
                case ADD_OVERWRITE -> {
                    if (change.indexOf(before.sessionOverwrites()) >= 0) setOverwriteKeys(lines, change, expected, stamp);
                    else addOverwrite(lines, change, stamp);
                }
                case ADD_OVERWRITE_KEYS, REMOVE_OVERWRITE_KEYS -> setOverwriteKeys(lines, change, expected, stamp);
                case SET_FIRST_PARAM -> setFirstParam(lines, change, stamp);
                case ADD_LOGIN_TYPE -> addToList(lines, "loginTypeNames", change, stamp);
                case ADD_LOGIN_PREFIX -> addToList(lines, "loginMethodPrefixes", change, stamp);
                case ADD_SCOPE_KEY -> addToList(lines, "userScopeKeys", change, stamp);
                case SET_FRAMEWORK -> writeFrameworks(lines, expected.frameworks());
            }
        }
        String result = String.join("\n", lines);
        if (!result.endsWith("\n")) result += "\n";
        TraceRules actual = TraceRules.parse(result);
        if (!actual.equals(expected)) {
            throw new IllegalStateException("trace-rules.yml을 자동으로 고치지 못했습니다 — 파일 모양이 예상과 다릅니다"
                    + "(키 목록을 [a, b] 한 줄로 쓰지 않았거나 항목 모양이 다름). 직접 반영하세요.");
        }
        return result;
    }

    /**
     * 판정에 쓰는 부분만(frameworks 섹션을 뺀 내용). 규칙셋 버전 해시에 넣는다 — 구조 기록만 바뀌었는데 규칙셋 버전이 바뀌면
     * 점검 이력에서 "판정 기준이 바뀌었다"로 잘못 읽힌다.
     */
    public static String judgmentPart(String content) {
        List<String> lines = new ArrayList<>(Arrays.asList(normalize(content).split("\n", -1)));
        int key = topKey(lines, FRAMEWORKS);
        if (key < 0) return String.join("\n", lines).strip();
        int from = blockStart(lines, key);
        int to = sectionEnd(lines, key);
        List<String> rest = new ArrayList<>(lines.subList(0, from));
        rest.addAll(lines.subList(to, lines.size()));
        return String.join("\n", rest).strip();
    }

    // ---------------------------------------------------------------- 목록(loginTypeNames 등)

    private static void addToList(List<String> lines, String key, TraceRuleChange change, String stamp) {
        String comment = "# " + stamp + ": " + key + "에 " + change.values() + " 추가 — " + firstEvidence(change);
        int at = topKey(lines, key);
        if (at < 0) {
            int insert = appendIndex(lines);
            List<String> block = new ArrayList<>();
            if (insert > 0 && !lines.get(insert - 1).isBlank()) block.add("");
            block.add(comment);
            block.add(key + ": [" + String.join(", ", change.values()) + "]");
            block.add("");
            lines.addAll(insert, block);
            return;
        }
        Matcher flow = FLOW_LIST.matcher(lines.get(at));
        if (flow.matches()) {
            List<String> items = new ArrayList<>(splitFlow(flow.group(2)));
            change.values().forEach(v -> { if (!items.contains(v)) items.add(v); });
            lines.set(at, flow.group(1) + "[" + String.join(", ", items) + "]" + (flow.group(3) == null ? "" : " " + flow.group(3)));
            lines.add(at, comment);
            return;
        }
        // 여러 줄 목록(- a): 섹션 끝에 항목을 더하고 근거는 그 위 주석으로.
        int end = sectionEnd(lines, at);
        String indent = itemIndent(lines, at, end);
        List<String> block = new ArrayList<>();
        block.add(indent + comment);
        change.values().forEach(v -> block.add(indent + "- " + v));
        lines.addAll(end, block);
    }

    // ---------------------------------------------------------------- 세션 덮어쓰기

    private static void addOverwrite(List<String> lines, TraceRuleChange change, String stamp) {
        int at = topKey(lines, "sessionOverwrites");
        if (at < 0) {
            int insert = appendIndex(lines);
            if (insert > 0 && !lines.get(insert - 1).isBlank()) lines.add(insert++, "");
            lines.add(insert, "sessionOverwrites:");
            lines.add(insert + 1, "");
            at = insert;
        } else if (lines.get(at).matches("sessionOverwrites:\\s*\\[\\s*]\\s*(#.*)?")) {
            lines.set(at, "sessionOverwrites:");
        }
        int end = sectionEnd(lines, at);
        String indent = end > at + 1 ? itemIndent(lines, at, end) : INDENT;
        List<String> block = new ArrayList<>();
        block.add(indent + "# " + stamp + " — " + change.system() + " 점검 초안. 근거:");
        change.evidence().forEach(e -> block.add(indent + "#   " + oneLine(e)));
        block.add(indent + "- name: " + quote(change.overwriteName()));
        block.add(indent + "  annotation: " + change.annotation());
        if (change.container() != null) block.add(indent + "  container: " + change.container());
        if (change.requiredFirstParam() != null) block.add(indent + "  requiredFirstParam: " + change.requiredFirstParam());
        block.add(indent + "  keys: [" + String.join(", ", change.values()) + "]");
        lines.addAll(end, block);
    }

    private static void setOverwriteKeys(List<String> lines, TraceRuleChange change, TraceRules expected, String stamp) {
        int[] item = findItem(lines, change);
        int keysLine = fieldLine(lines, item, "keys");
        if (keysLine < 0) throw new IllegalStateException("세션 덮어쓰기 항목에 keys 줄이 없습니다(@" + change.annotation() + ") — 직접 반영하세요.");
        Matcher flow = FLOW_LIST.matcher(lines.get(keysLine));
        if (!flow.matches()) throw new IllegalStateException("keys가 [a, b] 한 줄 모양이 아닙니다(@" + change.annotation() + ") — 직접 반영하세요.");
        TraceRules.SessionOverwrite after = expected.sessionOverwrites().get(change.indexOf(expected.sessionOverwrites()));
        lines.set(keysLine, flow.group(1) + "[" + String.join(", ", after.keys()) + "]" + (flow.group(3) == null ? "" : " " + flow.group(3)));
        String what = change.type() == TraceRuleChange.Type.REMOVE_OVERWRITE_KEYS ? " 제외(세션 값 아님)" : " 추가";
        lines.add(keysLine, indentOf(lines.get(keysLine)) + "# " + stamp + ": " + change.values() + what + " — " + firstKeyEvidence(change));
    }

    private static void setFirstParam(List<String> lines, TraceRuleChange change, String stamp) {
        int[] item = findItem(lines, change);
        int line = fieldLine(lines, item, "requiredFirstParam");
        int annotationLine = fieldLine(lines, item, "annotation");
        String indent = indentOf(lines.get(annotationLine)).length() > indentOf(lines.get(item[0])).length()
                ? indentOf(lines.get(annotationLine)) : indentOf(lines.get(item[0])) + INDENT;
        String comment = indent + "# " + stamp + ": 첫 파라미터 조건 → " + (change.requiredFirstParam() == null ? "없음" : change.requiredFirstParam());
        if (line >= 0) {
            if (change.requiredFirstParam() == null) lines.set(line, comment);
            else {
                lines.set(line, indentOf(lines.get(line)) + "requiredFirstParam: " + change.requiredFirstParam());
                lines.add(line, comment);
            }
        } else if (change.requiredFirstParam() != null) {
            lines.add(annotationLine + 1, indent + "requiredFirstParam: " + change.requiredFirstParam());
            lines.add(annotationLine + 1, comment);
        }
    }

    /** 같은 장치(어노테이션·위치)인 항목의 [시작 줄, 끝 줄(다음 항목 시작)]. */
    private static int[] findItem(List<String> lines, TraceRuleChange change) {
        int at = topKey(lines, "sessionOverwrites");
        if (at < 0) throw new IllegalStateException("sessionOverwrites 섹션이 없습니다 — 직접 반영하세요.");
        int end = sectionEnd(lines, at);
        List<Integer> starts = new ArrayList<>();
        for (int i = at + 1; i < end; i++) {
            if (lines.get(i).stripLeading().startsWith("- ")) starts.add(i);
        }
        for (int n = 0; n < starts.size(); n++) {
            int[] item = {starts.get(n), n + 1 < starts.size() ? starts.get(n + 1) : end};
            int annotationLine = fieldLine(lines, item, "annotation");
            int containerLine = fieldLine(lines, item, "container");
            String annotation = annotationLine < 0 ? null : fieldValue(lines.get(annotationLine)).replaceFirst("^@", "");
            String container = containerLine < 0 ? null : fieldValue(lines.get(containerLine));
            if (container != null && container.isEmpty()) container = null;
            if (change.annotation().equals(annotation) && Objects.equals(change.container(), container)) return item;
        }
        throw new IllegalStateException("세션 덮어쓰기 항목을 찾지 못했습니다(@" + change.annotation() + ") — 직접 반영하세요.");
    }

    /** 항목 안에서 "name:" 줄(항목 첫 줄의 "- name:"도). 주석 줄은 건너뛴다. 없으면 -1. */
    private static int fieldLine(List<String> lines, int[] item, String name) {
        for (int i = item[0]; i < item[1]; i++) {
            String text = lines.get(i).strip();
            if (text.startsWith("#")) continue;
            if (text.startsWith("- ")) text = text.substring(2).strip();
            if (text.startsWith(name + ":")) return i;
        }
        return -1;
    }

    private static String fieldValue(String line) {
        String text = line.strip();
        if (text.startsWith("- ")) text = text.substring(2).strip();
        String value = text.substring(text.indexOf(':') + 1).replaceAll("\\s+#.*$", "").strip();
        return value.replaceAll("^[\"']|[\"']$", "");
    }

    // ---------------------------------------------------------------- 프레임워크 구조

    private static void writeFrameworks(List<String> lines, Map<String, List<FrameworkFact>> frameworks) {
        int key = topKey(lines, FRAMEWORKS);
        if (key >= 0) {
            int from = blockStart(lines, key);
            int to = sectionEnd(lines, key);
            lines.subList(from, to).clear();
            // 섹션 앞뒤에 남은 빈 줄 정리 — 매번 다시 쓰면서 빈 줄이 쌓이지 않게.
            while (!lines.isEmpty() && lines.get(lines.size() - 1).isBlank()) lines.remove(lines.size() - 1);
        }
        if (frameworks.isEmpty()) return;
        int insert = lines.size();
        while (insert > 0 && lines.get(insert - 1).isBlank()) insert--;
        List<String> block = new ArrayList<>();
        if (insert > 0) block.add("");
        block.addAll(Arrays.asList(FRAMEWORKS_HEADER.split("\n")));
        block.add(FRAMEWORKS + ":");
        frameworks.forEach((system, facts) -> {
            block.add(INDENT + quote(system) + ":");
            for (FrameworkFact f : facts) {
                block.add(INDENT + "  - {kind: " + quote(f.kind()) + ", value: " + quote(f.value())
                        + ", evidence: " + quote(f.evidence() == null ? "" : f.evidence()) + "}");
            }
        });
        lines.subList(insert, lines.size()).clear();
        lines.addAll(block);
    }

    // ---------------------------------------------------------------- 줄 찾기

    /** 들여쓰기 없는 "key:" 줄. 없으면 -1. */
    private static int topKey(List<String> lines, String key) {
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.startsWith(key + ":")) return i;
        }
        return -1;
    }

    /** 섹션 내용의 끝(다음 최상위 줄 앞의 주석·빈 줄은 다음 섹션 몫). 여기에 줄을 넣으면 섹션 마지막에 붙는다. */
    private static int sectionEnd(List<String> lines, int key) {
        int last = key;
        for (int i = key + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) continue;
            if (!Character.isWhitespace(line.charAt(0))) break;
            last = i;
        }
        return last + 1;
    }

    /** 최상위 키 바로 위에 붙은 주석 줄들의 시작(그 키 설명). */
    private static int blockStart(List<String> lines, int key) {
        int start = key;
        while (start > 0 && lines.get(start - 1).startsWith("#")) start--;
        return start;
    }

    /** 새 최상위 섹션을 넣을 곳 — frameworks는 항상 맨 끝에 둔다. */
    private static int appendIndex(List<String> lines) {
        int key = topKey(lines, FRAMEWORKS);
        if (key >= 0) return blockStart(lines, key);
        int end = lines.size();
        while (end > 0 && lines.get(end - 1).isBlank()) end--;
        return end;
    }

    /** 섹션 안 목록 항목("- ")의 들여쓰기. 항목이 없으면 기본 두 칸. */
    private static String itemIndent(List<String> lines, int key, int end) {
        for (int i = key + 1; i < end; i++) {
            if (lines.get(i).stripLeading().startsWith("- ")) return indentOf(lines.get(i));
        }
        return INDENT;
    }

    private static String indentOf(String line) {
        int i = 0;
        while (i < line.length() && Character.isWhitespace(line.charAt(i))) i++;
        return line.substring(0, i);
    }

    // ---------------------------------------------------------------- 값

    private static List<String> splitFlow(String inner) {
        List<String> items = new ArrayList<>();
        for (String part : inner.split(",")) {
            String item = part.strip();
            if (!item.isEmpty()) items.add(item);
        }
        return items;
    }

    /** YAML 큰따옴표 문자열. 근거에 :·#·따옴표가 섞여도 한 값으로 읽히게. */
    static String quote(String value) {
        StringBuilder q = new StringBuilder("\"");
        for (char ch : value.toCharArray()) {
            switch (ch) {
                case '\\' -> q.append("\\\\");
                case '"' -> q.append("\\\"");
                case '\n', '\r', '\t' -> q.append(' ');
                default -> q.append(ch);
            }
        }
        return q.append('"').toString();
    }

    private static String firstEvidence(TraceRuleChange change) {
        return change.evidence().isEmpty() ? "" : oneLine(change.evidence().get(0));
    }

    /** 키를 바꾼 근거 — 어드바이스 위치보다 그 키를 넣는 줄이 더 직접적이다. */
    private static String firstKeyEvidence(TraceRuleChange change) {
        for (String e : change.evidence()) {
            for (String v : change.values()) {
                if (e.startsWith(v + " ")) return oneLine(e);
            }
        }
        return firstEvidence(change);
    }

    private static String oneLine(String text) {
        String line = text.replaceAll("\\s+", " ").strip();
        return line.length() > 200 ? line.substring(0, 197) + "..." : line;
    }

    private static String normalize(String content) {
        return content.replace("\r\n", "\n");
    }
}
