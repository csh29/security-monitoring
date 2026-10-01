package com.sjinc.cvemonitor.dto.scan;

import java.util.Map;
import java.util.Set;

/**
 * 스캔한 저장소 소스에서 뽑은 "무엇을 쓰는가" 목록. 업그레이드 영향 분석의 breaking change가 우리 코드에 해당하는지
 * 서버 안에서 대조하는 데 쓴다(CodeUsageMatcher) — 코드 본문은 물론 이 목록도 AI로 보내지 않는다.
 *
 * @param imports        import 대상("org.x.Foo" 또는 와일드카드 "org.x.*", static import는 멤버를 뗀 클래스) → 그 import가 있는 파일 수
 * @param configKeys     application*.properties / yml의 설정 키(값은 뺀다 — 비밀번호 같은 값이 섞여 있다)
 * @param javaFileCount  읽은 .java 파일 수. 0이면 소스를 못 읽은 것이라 "안 보임"을 믿을 수 없다
 */
public record SourceUsage(Map<String, Integer> imports, Set<String> configKeys, int javaFileCount) {
}
