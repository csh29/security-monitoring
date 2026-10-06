package com.sjinc.cvemonitor.service.securecode;

import com.sjinc.cvemonitor.domain.SecureCodeFinding;
import com.sjinc.cvemonitor.dto.securecode.DetectedFinding;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 이번 점검 결과를 그 앱의 기존 탐지와 맞춘다. 저장은 하지 않고 바꿀 엔티티만 돌려준다 — Spring 없이 테스트하기 위함.
 *
 * <ul>
 *   <li>지문이 처음 보는 것 → 새 OPEN</li>
 *   <li>지문이 이미 있음 → 위치·조각 갱신. 스캔이 RESOLVED로 만든 건이면 다시 OPEN(사람이 정한 상태는 유지)</li>
 *   <li>기존 OPEN인데 이번에 안 걸림 → RESOLVED. 단 두 경우는 그대로 둔다:
 *     그 파일을 Semgrep이 끝까지 못 봤을 때(못 본 것이지 고친 게 아니다),
 *     그 규칙이 이번 규칙셋에 없을 때(규칙을 지운 것이지 고친 게 아니다).</li>
 * </ul>
 */
public final class SecureCodeReconciler {

    private SecureCodeReconciler() {
    }

    /**
     * @param toSave        새로 만들었거나 바꾼 엔티티
     * @param newCount      점검 전엔 OPEN이 아니었는데 점검 후 OPEN인 건(처음 걸림 + 해결됐다가 다시 걸림)
     * @param resolvedCount 이번 점검으로 RESOLVED가 된 건
     */
    public record Result(List<SecureCodeFinding> toSave, int newCount, int resolvedCount) {
    }

    public static Result reconcile(Long appId, List<SecureCodeFinding> existing, List<DetectedFinding> detected,
                                   Set<String> failedFiles, Set<String> activeRuleIds, LocalDateTime now) {
        Map<String, SecureCodeFinding> byFingerprint = new HashMap<>();
        existing.forEach(finding -> byFingerprint.put(finding.getFingerprint(), finding));

        // 같은 지문이 한 번의 결과에 두 번 오면(지문 계산상 없어야 하지만) 유니크 제약 위반으로 점검 전체가 실패한다 — 첫 번째만 쓴다.
        Map<String, DetectedFinding> current = new LinkedHashMap<>();
        detected.forEach(d -> current.putIfAbsent(d.fingerprint(), d));

        List<SecureCodeFinding> toSave = new ArrayList<>();
        int newCount = 0;
        for (DetectedFinding d : current.values()) {
            SecureCodeFinding finding = byFingerprint.get(d.fingerprint());
            if (finding == null) {
                toSave.add(SecureCodeFinding.detect(appId, d, now));
                newCount++;
                continue;
            }
            boolean wasOpen = SecureCodeFinding.OPEN.equals(finding.getStatus());
            finding.redetect(d, now);
            if (!wasOpen && SecureCodeFinding.OPEN.equals(finding.getStatus())) {
                newCount++;
            }
            toSave.add(finding);
        }

        int resolvedCount = 0;
        for (SecureCodeFinding finding : existing) {
            if (current.containsKey(finding.getFingerprint())
                    || failedFiles.contains(finding.getFilePath())
                    || !activeRuleIds.contains(finding.getRuleId())) {
                continue;
            }
            if (finding.resolveByScan(now)) {
                toSave.add(finding);
                resolvedCount++;
            }
        }
        return new Result(toSave, newCount, resolvedCount);
    }
}
