package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 이번 점검 결과를 기존 탐지와 맞춰 바꿀 엔티티만 돌려준다(Spring 없이 테스트하려고 저장은 하지 않는다). 새 지문은 OPEN, 있던 지문은 갱신하고
 * 안 걸린 OPEN은 RESOLVED로 두되, 파일을 끝까지 못 봤거나 규칙이 빠진 경우는 고친 게 아니라 그대로 둔다.
 * 합쳐 빠진 건은 고친 것으로 오해하지 않게 비고에 이유를 남기며, 사람이 정한 상태는 유지한다.
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
        return reconcile(appId, existing, detected, failedFiles, activeRuleIds, Map.of(), now);
    }

    /** @param mergedAway 합쳐져 빠진 탐지의 지문 → 남은 규칙 id(DuplicateCweMerger.Merged) */
    public static Result reconcile(Long appId, List<SecureCodeFinding> existing, List<DetectedFinding> detected,
                                   Set<String> failedFiles, Set<String> activeRuleIds, Map<String, String> mergedAway,
                                   LocalDateTime now) {
        Map<String, SecureCodeFinding> byFingerprint = new HashMap<>();
        existing.forEach(finding -> byFingerprint.put(finding.getFingerprint(), finding));

        // 같은 지문이 두 번 오면 유니크 제약 위반으로 점검 전체가 실패하므로 첫 번째만 쓴다.
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
            if (current.containsKey(finding.getFingerprint())) continue;
            String keptRule = mergedAway.get(finding.getFingerprint());
            if (keptRule != null) {
                if (finding.retireRule("같은 위치의 " + keptRule + " 탐지와 한 건으로 합침", now)) {
                    toSave.add(finding);
                }
                continue;
            }
            if (failedFiles.contains(finding.getFilePath())
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
