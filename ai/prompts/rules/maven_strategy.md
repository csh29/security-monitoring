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

## Spring Boot 자신의 모듈은 3번(개별 override)으로 못 고친다

CVE가 지목한 아티팩트가 `org.springframework.boot:spring-boot`, `spring-boot-autoconfigure`, `spring-boot-actuator`, `spring-boot-devtools`, `spring-boot-starter-*` 등 **`org.springframework.boot` 그룹 자신의 모듈**이면, 3번(프로퍼티/`dependencyManagement` override)은 애초에 쓸 수 없다 — 시도해도 조용히 무시된다.

이유: `spring-boot-dependencies` BOM 안에서 이 모듈들의 버전은 `${spring-framework.version}`처럼 오버라이드 가능한 프로퍼티가 아니라 **그 BOM 자신의 버전 값이 리터럴로 박혀 있다**(예: `spring-boot-dependencies:3.2.6`의 `spring-boot-devtools` 항목은 `<version>3.2.6</version>`). 즉 이 모듈들의 버전을 바꾸는 유일한 방법은 **parent(`spring-boot-starter-parent`) 자체를 올리는 것**뿐이다 — 1번/2번(`PARENT_UPGRADE`)만 성립한다.

- 목표 버전이 현재 parent와 같은 마이너 라인의 패치 업그레이드로 도달 가능하면(예: `3.2.6` → `3.2.10`), 그건 메이저 업그레이드가 아니니 "자동으로 선택하지 마라" 규칙에 안 걸린다 — 1번 우선순위 그대로 적용해서 parent를 올려라.
- **주의**: `org.springframework.boot` 그룹의 모듈들은 서로 다른 Maven 좌표다. `spring-boot`만 `<dependencyManagement>`로 콕 집어 버전을 고정해도 `spring-boot-devtools`나 `spring-boot-starter-actuator`처럼 같은 릴리스로 묶여 나오는 다른 모듈에는 전혀 전파되지 않는다 — 서로 다른 CVE로 따로 잡혀도 실제로는 다 같은 parent 버전에 묶여 있으니, 이런 CVE가 여러 개 걸려있으면 parent 업그레이드 하나로 한꺼번에 묶어서 해소하는 게 맞다.
- 그래도 parent를 못 올리는 상황(더 낮은 마이너 라인에 패치가 없다, 메이저 업그레이드가 필요하다 등)이면 억지로 프로퍼티를 만들어내지 말고 `unresolved_cves`에 "parent 업그레이드 필요, 프로퍼티 override 불가" 로 적어라.

## 프로퍼티 오버라이드가 parent의 기본값과 너무 멀어지면 parent를 올리는 걸 우선 고려하라

3번(프로퍼티 override)을 쓸 때, 목표 버전이 **지금 parent 라인이 원래 관리하는 기본값과 몇 마이너 라인이나 떨어져 있는지**를 먼저 확인해라. 너무 멀면 그 프로퍼티 override 자체가 새로운 위험이 된다 — Spring Boot의 auto-configuration 코드는 자기 라인이 관리하는 버전 조합으로만 테스트됐지, 임의로 앞당긴 조합으로는 검증되지 않았다.

실제로 확인된 예: Spring Boot 3.2.x는 원래 Spring Framework 6.1.8 / Spring Security 6.2.4를 관리한다. 그런데 parent는 3.2.6에 그대로 두고 프로퍼티로 Framework를 6.2.19, Security를 6.5.11로 강제하면, 이건 오히려 Spring Boot **3.5.x가 원래 관리하는 조합**(Framework 6.2.7 / Security 6.5.0)에 더 가깝다 — 3.2.6의 auto-configuration이 한 번도 검증해본 적 없는 조합으로 억지로 밀어넣는 셈이다.

- 이런 낌새가 보이면(오버라이드하려는 버전이 지금 parent 라인의 기본값과 마이너 라인 기준 여러 단계 떨어져 있으면), parent 자체를 그 방향으로(메이저 업그레이드가 아닌 선에서) 올리는 걸 먼저 검토해라. parent를 올리면 그 라인이 원래 관리하는 조합에 더 가까워져서, 오버라이드해야 하는 폭도 줄고 검증 안 된 조합 리스크도 줄어든다.
  (예: 위 사례라면 parent를 3.5.x로 올리면 Framework는 오버라이드가 아예 필요 없어지고, Security만 6.5.0→6.5.11 정도의 작은 패치 오버라이드만 남는다 — 3.2.6에 6.5.11을 강제하는 것보다 훨씬 안전하다.)
- 그렇다고 이 판단 하나만으로 메이저 업그레이드를 자동 선택하지는 마라 — "메이저 업그레이드는 자동으로 선택하지 마라" 규칙이 여전히 우선한다. 같은 메이저 라인 안에서 더 가까운 마이너로 올릴 수 있는 경우에만 적용한다.
- reasoning에는 "프로퍼티 오버라이드가 parent 기본값과 이만큼 떨어져 있어 parent를 함께 올렸다" 또는 반대로 "거리가 크지 않아 parent는 그대로 두고 프로퍼티만 오버라이드했다"를 명시해라 — 이 판단을 왜 했는지 사람이 보고 검증할 수 있어야 한다.

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
