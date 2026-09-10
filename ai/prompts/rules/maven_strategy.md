# pom.xml 수정 전략 규칙

## 전략 선택 우선순위

위에서부터 시도하고, 되는 첫 번째를 택한다.

1. **부모 BOM의 패치 버전 업그레이드** (같은 마이너 라인 안에서)
   예: `spring-boot-starter-parent` `3.2.1` → `3.2.5`.
   이게 가장 안전하다. 관리 버전이 정합성 검증된 조합으로 함께 올라간다. → `PARENT_UPGRADE`

2. **부모 BOM의 마이너 업그레이드**
   예: `3.1.x` → `3.2.x`. 설정 프로퍼티 deprecation·자동설정 변경이 따라올 수 있다.
   택할 수는 있지만 reasoning에 영향 범위와 회귀 테스트 필요성을 반드시 적는다. → `PARENT_UPGRADE`

3. **개별 버전 override** — 부모를 못 올리거나, 부모를 올려도 해당 아티팩트가 목표 버전에 못 미칠 때. → `PROPERTY_OVERRIDE`

4. 둘을 섞어야 하면 → `MIXED`

**메이저 업그레이드는 자동으로 선택하지 마라.** 특히 Spring Boot 2.x → 3.x 는 Java 17 이상 + `javax.*` → `jakarta.*` 전면 수정 + Hibernate 5→6 이 따라오므로 pom 수정만으로 끝나지 않는다. 이런 경우는 3번 방식으로 우회하고, 우회가 불가능하면 `unresolved_cves` 에 "메이저 업그레이드 필요, 코드 수정 동반" 으로 적는다. Tomcat 9→10, Hibernate 5→6, Jakarta EE 8→9 도 같다.

## override 방법 선택 — 가장 흔한 실수

`<properties>` 에 `<netty.version>4.1.100.Final</netty.version>` 같은 걸 쓰는 방식은 **그 프로퍼티 이름이 부모 BOM에 실제로 정의돼 있을 때만** 동작한다. 이름을 틀리면 아무 효과 없이 조용히 무시되고, 취약점이 그대로 남은 채 "고쳤다"고 착각하게 된다.

- 부모 BOM(예: `spring-boot-dependencies`)이 그 프로퍼티를 정의한다고 **확실히 아는 경우에만** 프로퍼티 override 를 쓴다.
- 조금이라도 불확실하면 `<dependencyManagement>` 에 명시적 항목을 추가해 버전을 고정한다. 프로퍼티 이름에 의존하지 않으므로 항상 효과가 있다.

## 직접 의존성 vs 전이 의존성

`dependency:tree` 로 어느 쪽인지 먼저 확인한다.

- **직접 의존성**(pom에 `<dependency>` 로 선언됨): 해당 선언의 `<version>`, 또는 그 버전을 공급하는 프로퍼티를 수정한다.
- **전이 의존성**(pom에 선언 없음): `<dependencyManagement>` 에 항목을 추가해 버전만 고정한다.
  `<dependencies>` 에 직접 선언을 추가하지 마라. 컴파일 스코프로 노출되어 원래 안 쓰던 API를 코드에서 참조할 수 있게 되고, 의존성 구조가 바뀐다.

## 절대 하지 말 것

- 취약점과 무관한 의존성·플러그인·빌드 설정 변경
- 주석 삭제/이동, 요소 순서 변경, 들여쓰기·개행·인코딩 변경, XML 선언 변경
  → 원본을 그대로 보존하고 **필요한 라인만** 바꾼다. 리뷰 가능한 최소 diff가 목표다.
- 버전 다운그레이드
- 의존성 제거, 또는 `<exclusions>` 로 취약 라이브러리 배제
  → 런타임 `NoClassDefFoundError` 로 이어진다. 사용처를 모르는 상태에서 빼면 안 된다.
- 존재하지 않는 버전 발명 — 실존 릴리스가 확실한 버전만 쓴다. 불확실하면 `unresolved_cves` 로.
- `LATEST` / `RELEASE` / 버전 범위(`[1.0,2.0)`) 표기
- 새 리포지토리(`<repositories>`) 추가

## 호환성 확인 항목

수정안을 내기 전에 아래를 점검하고, 걸리는 게 있으면 `unresolved_cves` 나 `reasoning` 에 적는다.

- **Java 버전**: `maven.compiler.source/target/release`, `java.version` 프로퍼티. 목표 버전이 더 높은 Java를 요구하면 pom 수정만으로 안 된다. (Spring Boot 3.x = Java 17+, Spring Framework 6.x = Java 17+)
- **부모 BOM과의 정합성**: parent를 올리면 Spring Framework, Jackson, Netty, Tomcat, Hibernate 관리 버전이 함께 움직인다. 그중 코드에 영향 갈 수 있는 것을 reasoning에 나열한다.
- **다른 의존성이 요구하는 버전**: 특정 라이브러리를 단독으로 올렸을 때 그것을 쓰는 다른 라이브러리와 API 비호환이 생기는지. (예: Netty 단독 상향과 gRPC/Reactor 조합)
- **패키지 이동**: `javax.*` → `jakarta.*` 처럼 임포트 변경이 필요한 업그레이드는 pom만으로 완결되지 않는다.

## unresolved_cves 작성

버전만으로 해결 불가한 것을 CVE 단위로 적는다. 해당 없으면 빈 문자열.

각 항목에 이유를 함께 쓴다.
- 코드/설정 변경이 필요한 CVE (예: 역직렬화 화이트리스트 설정, 기능 비활성화)
- 수정 버전이 아직 없는 CVE
- 메이저 업그레이드가 필요해 이번 수정안에서 제외한 CVE
- 권장 최소 버전이 미확인(`null`)인 CVE
