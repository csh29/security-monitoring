package com.sjinc.securitymonitor.service.ai;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI(Claude API)로 보내는 저장소 원문에서 비밀값을 자리표시자로 가리고, 돌아온 결과에서 되돌린다.
 *
 * <p>지금 저장소 원문이 AI로 나가는 곳은 fix-plan의 pom.xml 하나다(FixPlanService). pom에는 DB 비밀번호 프로퍼티,
 * 계정이 든 저장소 URL(https://user:pass@nexus), 플러그인 설정의 JDBC URL(password=...)이 들어갈 수 있다.
 * AI가 고쳐 돌려주는 pom은 파일 전체라, 가린 채 저장하면 사람이 복사해 쓸 수 없다 — 그래서 받은 뒤 원래 값으로 되돌린다.
 *
 * <p>자리표시자는 {@code __MASKED_SECRET_<태그>_<번호>__}다. 태그는 "비밀값을 뺀 원문"의 해시 앞 8자리라, 보낸 뒤 재스캔으로
 * pom이 바뀌었으면 태그가 달라 되돌리지 않는다(엉뚱한 비밀값을 끼워 넣지 않게 — 자리표시자가 남아 사람이 알아본다).
 * 비밀값 자체의 해시는 보내지 않는다. 짧은 비밀번호는 해시만으로도 사전 대입으로 알아낼 수 있다.
 *
 * <p>가리는 것: 이름이 비밀값처럼 보이는 XML 요소의 값, URL의 계정 정보, {@code password=}류 키=값, 형식이 알려진 토큰
 * (AWS·GitHub·GitLab·Slack·JWT·개인키 블록). {@code ${프로퍼티}} 참조는 비밀값이 아니라 그대로 둔다.
 * 판단이 애매하면 가린다 — 더 가려서 잃는 건 AI가 그 값을 못 보는 것뿐이고, 되돌리므로 결과물은 깨지지 않는다.
 */
public final class SecretMasker {

    /** 가린 원문과 되돌리기 위한 대응표(자리표시자 → 원래 값). */
    public record Masked(String text, Map<String, String> secrets) {
    }

    private static final String SECRET_NAME =
            "(?:password|passwd|pwd|secret|token|api[._-]?key|access[._-]?key|secret[._-]?key|private[._-]?key|credentials?|passphrase|username|storepass|keypass)";
    /** {@code <db.password>값</db.password>} — 요소 이름에 비밀값 이름이 들어 있으면 값 전체. */
    private static final Pattern XML_ELEMENT = Pattern.compile(
            "(?i)<([\\w.:-]*" + SECRET_NAME + "[\\w.:-]*)(\\s[^>]*)?>([^<]+)</\\1>");
    /** {@code scheme://user:pass@host} 의 user:pass. */
    private static final Pattern URL_USERINFO = Pattern.compile("[a-zA-Z][\\w+.-]*://([^/\\s:@<>\"']+:[^/\\s@<>\"']+)@");
    /** {@code password=값}, {@code -Dapi.key=값}, JDBC URL 파라미터. */
    private static final Pattern KEY_VALUE = Pattern.compile(
            "(?i)" + SECRET_NAME + "\\s*[=:]\\s*([^\\s&;<>\"',)]+)");
    /** 형식이 알려진 토큰·키. 이름 없이 값만 있어도 잡는다. */
    private static final Pattern KNOWN_TOKEN = Pattern.compile(
            "AKIA[0-9A-Z]{16}"
                    + "|gh[pousr]_[A-Za-z0-9]{30,}"
                    + "|glpat-[A-Za-z0-9_-]{20,}"
                    + "|xox[baprs]-[A-Za-z0-9-]{10,}"
                    + "|eyJ[\\w-]{10,}\\.[\\w-]{10,}\\.[\\w-]{10,}"
                    + "|-----BEGIN[A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END[A-Z ]*PRIVATE KEY-----");
    private static final Pattern PROPERTY_REFERENCE = Pattern.compile("^\\s*\\$\\{[^}]+}\\s*$");
    private static final Pattern PLACEHOLDER = Pattern.compile("__MASKED_SECRET_([0-9a-f]{8})_(\\d+)__");

    private SecretMasker() {
    }

    public static Masked mask(String text) {
        if (text == null || text.isEmpty()) {
            return new Masked(text, Map.of());
        }
        List<int[]> spans = new ArrayList<>();
        collect(spans, XML_ELEMENT.matcher(text), 3);
        collect(spans, URL_USERINFO.matcher(text), 1);
        collect(spans, KEY_VALUE.matcher(text), 1);
        collect(spans, KNOWN_TOKEN.matcher(text), 0);
        List<int[]> merged = merge(spans);

        // 1차: 번호만 붙인 원문으로 태그를 만든다(태그 = 비밀값을 뺀 원문의 해시).
        StringBuilder neutral = new StringBuilder();
        int last = 0;
        for (int i = 0; i < merged.size(); i++) {
            neutral.append(text, last, merged.get(i)[0]).append("__MASKED_SECRET_").append(i + 1).append("__");
            last = merged.get(i)[1];
        }
        neutral.append(text.substring(last));
        String tag = sha256(neutral.toString()).substring(0, 8);

        StringBuilder masked = new StringBuilder();
        Map<String, String> secrets = new LinkedHashMap<>();
        last = 0;
        for (int i = 0; i < merged.size(); i++) {
            int[] span = merged.get(i);
            String placeholder = "__MASKED_SECRET_" + tag + "_" + (i + 1) + "__";
            masked.append(text, last, span[0]).append(placeholder);
            secrets.put(placeholder, text.substring(span[0], span[1]));
            last = span[1];
        }
        masked.append(text.substring(last));
        return new Masked(masked.toString(), secrets);
    }

    /**
     * AI 결과의 자리표시자를 원래 값으로 되돌린다. secrets는 지금 원문을 다시 mask해 얻은 대응표다 — 원문이 그사이 바뀌었으면
     * 태그가 달라 대응표에 없으므로 되돌리지 않고 남긴다.
     *
     * @return 되돌린 결과와, 되돌리지 못하고 남은 자리표시자 수
     */
    public static Unmasked unmask(String text, Map<String, String> secrets) {
        if (text == null) return new Unmasked(null, 0);
        Matcher m = PLACEHOLDER.matcher(text);
        StringBuilder result = new StringBuilder();
        int left = 0;
        while (m.find()) {
            String original = secrets.get(m.group());
            if (original == null) left++;
            m.appendReplacement(result, Matcher.quoteReplacement(original != null ? original : m.group()));
        }
        m.appendTail(result);
        return new Unmasked(result.toString(), left);
    }

    public record Unmasked(String text, int remainingPlaceholders) {
    }

    private static void collect(List<int[]> spans, Matcher m, int group) {
        while (m.find()) {
            int start = m.start(group), end = m.end(group);
            String value = m.group(group);
            if (value.isBlank() || PROPERTY_REFERENCE.matcher(value).matches()) continue;
            // 값 앞뒤 공백은 남긴다(들여쓰기·줄바꿈을 바꾸지 않게).
            while (start < end && Character.isWhitespace(value.charAt(start - m.start(group)))) start++;
            while (end > start && Character.isWhitespace(value.charAt(end - 1 - m.start(group)))) end--;
            if (start < end) spans.add(new int[]{start, end});
        }
    }

    /** 겹치거나 맞닿은 구간을 합친다(같은 비밀값이 여러 패턴에 걸려도 자리표시자 하나). */
    private static List<int[]> merge(List<int[]> spans) {
        spans.sort((a, b) -> a[0] != b[0] ? Integer.compare(a[0], b[0]) : Integer.compare(b[1], a[1]));
        List<int[]> merged = new ArrayList<>();
        for (int[] span : spans) {
            if (!merged.isEmpty() && span[0] < merged.get(merged.size() - 1)[1]) {
                int[] prev = merged.get(merged.size() - 1);
                prev[1] = Math.max(prev[1], span[1]);
            } else {
                merged.add(new int[]{span[0], span[1]});
            }
        }
        return merged;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
