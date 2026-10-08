package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 같은 규칙이 한 식 안에 겹쳐 걸린 탐지를 바깥 한 건으로 합친다. 규칙은 위험한 지점을 빠짐없이 적어 두므로
 * ({@code new File(...)}·{@code new FileInputStream(...)} 둘 다 실행 지점) {@code new FileInputStream(new File(fileName))}은
 * 같은 값 하나가 두 지점에 걸려 두 건이 된다(OWASP Benchmark 경로 조작). 걸린 범위가 다른 범위 안에 통째로 들어가면 안쪽을 뺀다.
 *
 * <p>나란히 걸린 것(한 줄의 {@code ${a}}·{@code ${b}})은 범위가 겹치지 않아 그대로 둔다 — 값마다 판정이 다르다.
 * 다른 규칙끼리는 여기서 보지 않는다(같은 줄·같은 CWE는 DuplicateCweMerger). 열을 모르는 탐지(0)도 그대로 둔다.
 *
 * <p>지문은 걸린 모든 탐지로 만든 뒤에 뺀다 — 파일 안 등장 순서가 지문에 들어가서(SecureCodeSnippetBuilder), 먼저 빼면 남는 건의 지문이 바뀐다.
 */
public final class NestedMatchMerger {

    private NestedMatchMerger() {
    }

    /**
     * @param matches  Semgrep 결과(열 포함)
     * @param detected matches로 만든 탐지 — 같은 순서·같은 개수(SecureCodeSnippetBuilder.build)
     * @return 안쪽을 뺀 탐지와, 빠진 탐지의 지문 → 남은 규칙 id(기존 탐지는 "고쳐서 해결"이 아니라 합친 것으로 정리된다)
     */
    public static DuplicateCweMerger.Merged merge(List<SemgrepMatch> matches, List<DetectedFinding> detected) {
        if (matches.size() != detected.size()) {
            throw new IllegalArgumentException("탐지 수가 Semgrep 결과 수와 다릅니다: " + detected.size() + " / " + matches.size());
        }
        List<DetectedFinding> result = new ArrayList<>(detected.size());
        Map<String, String> mergedAway = new LinkedHashMap<>();
        for (int i = 0; i < matches.size(); i++) {
            if (insideAnother(matches, i)) {
                mergedAway.put(detected.get(i).fingerprint(), matches.get(i).ruleId());
            } else {
                result.add(detected.get(i));
            }
        }
        return new DuplicateCweMerger.Merged(mergedAway.isEmpty() ? detected : result, mergedAway);
    }

    /** i번째가 같은 규칙·같은 파일의 다른 탐지 범위 안에 들어가는가. 범위가 똑같으면 앞의 것을 남긴다. */
    private static boolean insideAnother(List<SemgrepMatch> matches, int i) {
        SemgrepMatch inner = matches.get(i);
        if (inner.startCol() <= 0) return false;
        for (int j = 0; j < matches.size(); j++) {
            SemgrepMatch outer = matches.get(j);
            if (j == i || outer.startCol() <= 0 || !outer.ruleId().equals(inner.ruleId())
                    || !outer.filePath().equals(inner.filePath())) {
                continue;
            }
            boolean contains = compare(outer.startLine(), outer.startCol(), inner.startLine(), inner.startCol()) <= 0
                    && compare(inner.endLine(), inner.endCol(), outer.endLine(), outer.endCol()) <= 0;
            boolean same = compare(outer.startLine(), outer.startCol(), inner.startLine(), inner.startCol()) == 0
                    && compare(outer.endLine(), outer.endCol(), inner.endLine(), inner.endCol()) == 0;
            if (contains && (!same || j < i)) return true;
        }
        return false;
    }

    private static int compare(int line1, int col1, int line2, int col2) {
        return line1 != line2 ? Integer.compare(line1, line2) : Integer.compare(col1, col2);
    }
}
