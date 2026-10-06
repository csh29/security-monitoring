package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.dto.ai.CodeUsageView;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest.BreakingChange;
import com.sjinc.securitymonitor.dto.scan.SourceUsage;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * breaking change의 관련 이름(symbols)을 앱의 import·설정 키 목록과 대조한다. AI를 부르지 않고, 코드 정보도 서버 밖으로
 * 나가지 않는다.
 *
 * <p><b>"사용 발견"은 보수적으로 준다.</b> 정확한 클래스 전체 이름, 패키지, 설정 키가 일치할 때만 USED다. 패키지 이름은 프롬프트가
 * "패키지 전체가 옮겨지거나 제거됐을 때만" 쓰게 하므로(javax.servlet 등) 그 패키지에서 import하면 확실히 영향을 받는다. 짧은 클래스
 * 이름("Configuration")은 이름만 같은 다른 패키지의 클래스일 수 있고, 와일드카드 import(p.*)는 그 패키지의 다른 클래스만 쓰는
 * 것일 수 있어서 POSSIBLE로 낮춘다 — 틀린 "사용 발견"은 개발자가 없는 문제를 찾게 만든다.
 *
 * <p><b>반대로 NOT_FOUND는 "영향 없음"이 아니다.</b> import 없이 전체 이름으로 쓰거나, 리플렉션·XML·어노테이션 문자열로 쓰거나, 다른
 * 라이브러리를 거쳐 영향받는 경우는 import 목록에 나타나지 않는다. 화면도 "import에서 안 보임"으로만 보여준다.
 */
public final class CodeUsageMatcher {

    public static final String USED = "USED";
    public static final String POSSIBLE = "POSSIBLE";
    public static final String NOT_FOUND = "NOT_FOUND";
    public static final String UNKNOWN = "UNKNOWN";

    private CodeUsageMatcher() {
    }

    public static CodeUsageView match(List<BreakingChange> changes, SourceUsage usage) {
        if (usage == null || usage.javaFileCount() == 0) {
            // 목록이 없을 때 "안 보임"이라고 하면 영향 없음처럼 읽힌다. 전부 판단 불가로 둔다.
            List<CodeUsageView.Item> items = changes.stream().map(c -> new CodeUsageView.Item(UNKNOWN, List.of())).toList();
            return new CodeUsageView(UNKNOWN, items,
                    "이 앱의 소스 사용 목록이 없다(이 기능이 생기기 전 스캔이거나 추출 실패). 다시 스캔하면 채워진다.");
        }

        List<CodeUsageView.Item> items = new ArrayList<>();
        for (BreakingChange change : changes) {
            items.add(matchItem(change.symbols(), usage));
        }
        return new CodeUsageView(overall(items), items, null);
    }

    private static CodeUsageView.Item matchItem(List<String> symbols, SourceUsage usage) {
        if (symbols == null || symbols.isEmpty()) {
            return new CodeUsageView.Item(UNKNOWN, List.of()); // 이름으로 가리킬 수 없는 변경(기본 동작 변경 등)이거나 예전 분석 결과
        }
        List<String> used = new ArrayList<>();
        List<String> possible = new ArrayList<>();
        for (String symbol : symbols) {
            matchSymbol(symbol, usage, used, possible);
        }
        if (!used.isEmpty()) {
            return new CodeUsageView.Item(USED, used);
        }
        return possible.isEmpty() ? new CodeUsageView.Item(NOT_FOUND, List.of()) : new CodeUsageView.Item(POSSIBLE, possible);
    }

    /** 하나라도 USED면 USED, 아니면 POSSIBLE, 판단 불가가 섞여 있으면 UNKNOWN — 일부만 "안 보임"이어도 전체를 안 보임이라 할 수 없다. */
    private static String overall(List<CodeUsageView.Item> items) {
        if (items.stream().anyMatch(i -> USED.equals(i.status()))) return USED;
        if (items.stream().anyMatch(i -> POSSIBLE.equals(i.status()))) return POSSIBLE;
        if (items.stream().anyMatch(i -> UNKNOWN.equals(i.status()))) return UNKNOWN;
        return NOT_FOUND;
    }

    static void matchSymbol(String rawSymbol, SourceUsage usage, List<String> used, List<String> possible) {
        String symbol = toTypeName(rawSymbol);
        if (symbol.isEmpty()) {
            return;
        }

        // 설정 키: 정확히 같거나, 이름이 바뀐 접두어(spring.redis → spring.redis.host)를 쓰면 사용이다. Spring은 kebab/camel/밑줄을
        // 같은 키로 보므로(relaxed binding) 그 차이는 무시한다.
        // 점이 없는 이름("server")은 접두어로 거의 모든 키에 걸리고, 클래스처럼 보이는 이름("Server")은 대소문자를 무시하는 비교에서
        // 엉뚱한 키와 맞으므로 설정 키 대조에서 뺀다.
        boolean isQualified = symbol.contains(".");
        boolean isClass = startsWithUpper(lastSegment(symbol));
        if (isQualified && !isClass) {
            String relaxedSymbol = relaxed(symbol);
            for (String key : usage.configKeys()) {
                String relaxedKey = relaxed(key);
                if (relaxedKey.equals(relaxedSymbol) || relaxedKey.startsWith(relaxedSymbol + ".")) {
                    used.add("설정 키 " + key);
                }
            }
        }

        for (Map.Entry<String, Integer> entry : usage.imports().entrySet()) {
            String target = entry.getKey();
            String label = target + " (파일 " + entry.getValue() + "곳)";
            if (target.endsWith(".*")) {
                String importedPackage = target.substring(0, target.length() - 2);
                if (isQualified && !isClass && (importedPackage.equals(symbol) || importedPackage.startsWith(symbol + "."))) {
                    used.add(label); // 영향받는 패키지(또는 그 하위)를 통째로 import
                } else if (isQualified && isClass && symbol.startsWith(importedPackage + ".")) {
                    possible.add(label); // import p.* 에 대상 p.Foo — 그 클래스를 실제로 쓰는지는 import만으로 모른다
                }
            } else if (isQualified && isClass) {
                if (target.equals(symbol) || target.startsWith(symbol + ".")) {
                    used.add(label); // 정확한 클래스(또는 그 안의 중첩 클래스)
                }
            } else if (isQualified) {
                if (target.startsWith(symbol + ".")) {
                    used.add(label); // 영향받는 패키지의 클래스를 import
                }
            } else if (isClass && target.endsWith("." + symbol)) {
                possible.add(label); // 짧은 이름 일치 — 이름만 같은 다른 클래스일 수 있다
            }
        }
    }

    /**
     * 모델이 준 이름을 대조할 형태로. 메서드·필드까지 붙어 오면 클래스까지만 남긴다 — import는 클래스 단위라서다.
     * "Foo#bar" → "Foo", "org.x.Foo.bar()" → "org.x.Foo", "org.x.Foo.BAR" 같은 상수는 그대로 두면 클래스로 오인되지만
     * import 대상과 일치할 일이 없어 무해하다.
     */
    static String toTypeName(String rawSymbol) {
        String symbol = rawSymbol == null ? "" : rawSymbol.trim();
        int hash = symbol.indexOf('#');
        if (hash >= 0) {
            symbol = symbol.substring(0, hash);
        }
        if (symbol.endsWith("()")) {
            symbol = symbol.substring(0, symbol.length() - 2);
            int dot = symbol.lastIndexOf('.');
            symbol = dot > 0 ? symbol.substring(0, dot) : "";
        } else {
            // "org.x.Foo.bar"처럼 클래스 뒤에 소문자로 시작하는 멤버가 붙은 경우
            int dot = symbol.lastIndexOf('.');
            if (dot > 0 && !startsWithUpper(symbol.substring(dot + 1)) && startsWithUpper(lastSegment(symbol.substring(0, dot)))) {
                symbol = symbol.substring(0, dot);
            }
        }
        return symbol;
    }

    private static String lastSegment(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }

    private static boolean startsWithUpper(String value) {
        return !value.isEmpty() && Character.isUpperCase(value.charAt(0));
    }

    private static String relaxed(String key) {
        return key.replace("-", "").replace("_", "").toLowerCase(Locale.ROOT);
    }
}
