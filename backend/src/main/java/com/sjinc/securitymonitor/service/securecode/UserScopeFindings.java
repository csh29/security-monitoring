package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 사용자 범위 키(trace-rules.yml userScopeKeys)가 쓰인 매퍼 SQL의 연계 추적 판정(MybatisDollarTracer.Result.scopeVerdicts)을 탐지로 만든다.
 *
 * <p>약점은 "회사·브랜드·사용자로 데이터를 가르는 SQL 조건의 값을 클라이언트가 정할 수 있다"이다(행안부 "부적절한 인가", CWE-639 — 사용자가
 * 정하는 키로 인가 우회). 예전 Semgrep 규칙(kisa-authz-missing-user-scope)은 "특정 시스템의 장치(@AddUserInfo)가 없는 컨트롤러 메서드"를
 * 찾아서, 그 장치를 쓰지 않는 시스템은 전부 오탐이 되고, 사용자 범위 조건을 쓰지 않는 메서드도 걸렸다. 여기서는 조건이 실제로 쓰인 SQL 줄에서
 * 값의 출처를 판정하므로 시스템마다 다른 것은 키 이름(설정)뿐이다.
 *
 * <p>위험한 판정만 탐지로 낸다 — 클라이언트 값·공통 경로로 우회 가능(HIGH), 판정 불가(MEDIUM). 세션 덮어쓰기·서버 세팅·XML 결정은 안전이라
 * 내지 않는다(Semgrep 탐지가 아니라 판정에서 만든 탐지라, 안전한 것까지 내면 거의 모든 SQL이 목록에 오른다).
 *
 * <p>코드 조각·지문은 Semgrep 탐지와 같은 방법(SecureCodeSnippetBuilder)으로 만든다 — 재점검 비교·처리여부 유지가 똑같이 동작해야 한다.
 */
public final class UserScopeFindings {

    /** 판정에서 만든 탐지의 규칙 id. Semgrep 규칙 폴더에는 없다 — 점검이 이 판정을 했을 때만 활성 규칙에 넣는다(SecureCodeScanService). */
    public static final String RULE_ID = "kisa-authz-client-user-scope";
    static final String KISA_CATEGORY = "보안기능";
    static final String KISA_NAME = "부적절한 인가";
    static final String CWE = "CWE-639";

    private UserScopeFindings() {
    }

    public static List<DetectedFinding> build(List<DollarVerdict> scopeVerdicts, SecureCodeSnippetBuilder snippetBuilder)
            throws IOException {
        List<DollarVerdict> risky = scopeVerdicts.stream().filter(v -> !v.safety().isSafe()).toList();
        List<SemgrepMatch> matches = new ArrayList<>(risky.size());
        for (DollarVerdict v : risky) {
            matches.add(new SemgrepMatch(RULE_ID, KISA_CATEGORY, KISA_NAME, CWE, v.safety().severity(),
                    v.path(), v.line(), v.line(), message(v)));
        }
        List<DetectedFinding> detected = snippetBuilder.build(matches);
        List<DetectedFinding> result = new ArrayList<>(detected.size());
        for (int i = 0; i < detected.size(); i++) {
            DollarVerdict v = risky.get(i);
            result.add(detected.get(i).withTrace(v.safety().severity(), v.safety().name(), String.join("\n", v.evidence())));
        }
        return result;
    }

    static String message(DollarVerdict v) {
        String key = "#{" + v.expr() + "}";
        return switch (v.safety()) {
            case CLIENT -> "사용자 범위 조건 " + key + "의 값을 클라이언트가 보낸 값으로 씁니다. 다른 회사·사용자의 데이터를 조회·변경할 수 있으니 "
                    + "서버(세션·로그인 정보)에서 값을 넣으세요. 값이 지나온 길은 연계 추적 근거를 보세요.";
            case BYPASSABLE -> "사용자 범위 조건 " + key + "을 서비스 경로에서는 서버가 넣지만, 클라이언트가 구문 id를 정하는 공통 실행 경로로 이 구문을 "
                    + "직접 부르면 클라이언트 값이 들어갑니다. 공통 실행 경로에 구문 허용 목록을 두거나 그 경로에서도 서버 값으로 덮어쓰세요.";
            default -> "사용자 범위 조건 " + key + "의 값 출처를 끝까지 따라가지 못했습니다. 연계 추적 근거가 끊긴 곳에서 값이 서버(세션)에서 오는지 확인하세요.";
        };
    }
}
