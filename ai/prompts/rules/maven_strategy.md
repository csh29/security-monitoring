# pom.xml 수정 전략 규칙

## 전략 선택 우선순위

위에서부터 시도하고, 되는 첫 번째를 택한다. **기본값은 parent를 건드리지 않고 취약한 아티팩트만 개별 프로퍼티로 올리는 것이다.**

1. **개별 프로퍼티 override** — 부모 BOM이 정의한 버전 프로퍼티를 `<properties>` 에서 목표 버전으로 지정한다. → `PROPERTY_OVERRIDE`
   예: netty 계열(`netty-codec-http`, `netty-codec`, `netty-handler`, `netty-codec-http2`, `netty-resolver-dns`, `netty-codec-dns` …)이 취약하면
   parent는 그대로 두고 `<netty.version>4.1.118.Final</netty.version>` 한 줄로 해소한다.
   바뀌는 범위가 그 라이브러리 하나로 한정되어 diff가 가장 작고, 영향 범위를 사람이 바로 파악할 수 있다.
   - 프로퍼티 이름을 모르는 아티팩트는 `<dependencyManagement>` 명시 항목으로 고정한다(아래 "override 방법 선택" 참고).

2. **부모 BOM의 패치 버전 업그레이드** (같은 마이너 라인 안에서만)
   예: `spring-boot-starter-parent` `3.2.1` → `3.2.5`. → `PARENT_UPGRADE`
   아래 경우에만 택한다.
   - 1번이 **불가능**할 때 — 대표적으로 `org.springframework.boot` 그룹 자신의 모듈(아래 절 참고).
   - 취약 아티팩트가 너무 많아 프로퍼티를 여러 개 나열하는 것보다, 같은 마이너 라인의 패치 한 번이 전부를 덮을 때.

3. **부모 BOM의 마이너 이상 업그레이드는 하지 않는다.**
   예: `3.2.x` → `3.3.x` / `3.5.x`. 설정 프로퍼티 deprecation·자동설정 변경·관리 버전 대량 변경이 따라와서, pom 한 줄로 보이지만
   실제로는 검증되지 않은 변경이 된다. 그래서 1·2번이 모두 불가능한 CVE가 있어도 **parent 마이너를 올리지 마라** — parent는 현재 버전
   (또는 2번의 같은 마이너 라인 패치)에 그대로 두고, 그 CVE만 `unresolved_cves` 에
   "parent 마이너 업그레이드 필요(현재 3.2.6 → 최소 3.3.11), 사람 검토 필요" 처럼 **필요한 최소 parent 버전과 함께** 넘긴다.
   나머지 CVE는 평소대로 1번(개별 프로퍼티)으로 해소한다 — parent 마이너 업그레이드가 필요한 CVE가 하나 있다고 전체를 포기하지 않는다.

4. 둘을 섞어야 하면(예: Spring Boot 모듈 CVE 때문에 parent 패치 업그레이드 + netty는 프로퍼티) → `MIXED`

### "parent가 검증한 조합을 깨뜨린다"는 이유로 프로퍼티 override를 피하지 마라

같은 라인 안의 패치 업그레이드(예: netty `4.1.110.Final` → `4.1.118.Final`, Tomcat `10.1.19` → `10.1.34`, Jackson `2.15.3` → `2.15.4`)는
하위 호환이 유지되는 보안·버그 수정 릴리스다. 이런 프로퍼티 override는 Spring Boot 공식 문서가 안내하는 표준 방식이며,
"reactor-netty가 검증한 조합이라 netty.version 강제 지정은 위험하다 → parent를 올린다"는 판단은 **틀린 방향**이다 —
parent를 올리면 netty 하나가 아니라 Spring Framework·Security·Jackson·Tomcat 등 수십 개 관리 버전이 동시에 바뀌어 검증 범위가 훨씬 커진다.
reasoning에는 "같은 라인 패치 override라 호환성 영향이 작아 parent는 그대로 두었다"를 적는다.

**메이저 업그레이드는 자동으로 선택하지 마라.** 특히 Spring Boot 2.x → 3.x 는 Java 17 이상 + `javax.*` → `jakarta.*` 전면 수정 + Hibernate 5→6 이 따라오므로 pom 수정만으로 끝나지 않는다. 이런 경우는 1번(개별 프로퍼티) 방식으로 우회하고, 우회가 불가능하면 `unresolved_cves` 에 "메이저 업그레이드 필요, 코드 수정 동반" 으로 적는다. Tomcat 9→10, Hibernate 5→6, Jakarta EE 8→9 도 같다.

## Spring Boot 자신의 모듈은 1번(개별 override)으로 못 고친다

CVE가 지목한 아티팩트가 `org.springframework.boot:spring-boot`, `spring-boot-autoconfigure`, `spring-boot-actuator`, `spring-boot-devtools`, `spring-boot-starter-*` 등 **`org.springframework.boot` 그룹 자신의 모듈**이면, 1번(프로퍼티/`dependencyManagement` override)은 애초에 쓸 수 없다 — 시도해도 조용히 무시된다.

이유: `spring-boot-dependencies` BOM 안에서 이 모듈들의 버전은 `${spring-framework.version}`처럼 오버라이드 가능한 프로퍼티가 아니라 **그 BOM 자신의 버전 값이 리터럴로 박혀 있다**(예: `spring-boot-dependencies:3.2.6`의 `spring-boot-devtools` 항목은 `<version>3.2.6</version>`). 즉 이 모듈들의 버전을 바꾸는 유일한 방법은 **parent(`spring-boot-starter-parent`) 자체를 올리는 것**뿐이다 — 2번(`PARENT_UPGRADE`, 같은 마이너 라인 패치)만 성립하고, 그게 안 되면 `unresolved_cves` 다.

- 목표 버전이 현재 parent와 같은 마이너 라인의 패치 업그레이드로 도달 가능하면(예: `3.2.6` → `3.2.10`), 2번 우선순위 그대로 적용해서 parent를 올려라. 이때 같은 pom의 다른 취약 아티팩트(netty 등)는 parent 패치로 덮이지 않는 만큼만 프로퍼티로 올린다(`MIXED`).
- 같은 마이너 라인에 수정 패치가 없어 마이너를 올려야만 하면, 3번 규칙대로 parent는 올리지 말고 `unresolved_cves` 에 "parent 마이너 업그레이드 필요, 프로퍼티 override 불가" 와 필요한 최소 parent 버전을 적는다.
- **주의**: `org.springframework.boot` 그룹의 모듈들은 서로 다른 Maven 좌표다. `spring-boot`만 `<dependencyManagement>`로 콕 집어 버전을 고정해도 `spring-boot-devtools`나 `spring-boot-starter-actuator`처럼 같은 릴리스로 묶여 나오는 다른 모듈에는 전혀 전파되지 않는다 — 서로 다른 CVE로 따로 잡혀도 실제로는 다 같은 parent 버전에 묶여 있으니, 이런 CVE가 여러 개 걸려있으면 (같은 마이너 라인 안의) parent 패치 업그레이드 하나로 한꺼번에 묶어서 해소하고, 그게 안 되면 `unresolved_cves` 에도 한 항목으로 묶어 적는다.
- 어느 경우든 억지로 프로퍼티를 만들어내지 마라 — 시도해도 조용히 무시돼 "고쳤다"고 착각하게 된다.

## 프로퍼티 오버라이드의 거리 판단 — 멀다고 바로 parent를 올리지 마라

1번(프로퍼티 override)을 쓸 때, 목표 버전이 **지금 parent 라인이 원래 관리하는 기본값에서 얼마나 떨어져 있는지**를 확인하고 reasoning에 적는다.

- **같은 마이너 라인 안의 패치 차이**(예: netty `4.1.110.Final` → `4.1.118.Final`, Security `6.2.4` → `6.2.8`): 거리 문제 없음. 그대로 프로퍼티 override 한다. parent를 올릴 이유가 되지 않는다.
- **마이너 라인이 달라지는 경우**(예: parent 3.2.x가 Framework 6.1.x를 관리하는데 6.2.x로 강제): Spring Boot auto-configuration이 검증하지 않은 조합이 될 수 있다.
  먼저 **현재 마이너 라인 안에 수정 패치가 있는지** 확인해서, 있으면 그 패치 버전을 목표로 삼는다(예: 6.2.19가 아니라 6.1.x의 수정 패치).
  현재 라인에 패치가 없어 라인을 넘겨야만 할 때만 라인을 넘기되, reasoning의 [함께 검증 필요]에 "parent 기본값과 마이너 라인이 달라 auto-configuration 호환성 회귀 테스트 필요"를 적는다.
  이 경우에도 parent 마이너 업그레이드로 갈아타지 말고 프로퍼티 override를 유지한다(parent 마이너 업그레이드는 3번 규칙대로 하지 않는다).
- **메이저가 달라지는 경우**(예: Security 5.x → 6.x): 프로퍼티로도 강제하지 말고 `unresolved_cves` 로 넘긴다.
- reasoning에는 "같은 라인 패치 override라 parent는 그대로 두었다" 또는 "라인을 넘기는 override라 회귀 테스트가 필요하다"를 명시해라 — 이 판단을 왜 했는지 사람이 보고 검증할 수 있어야 한다.

## override 방법 선택 — 가장 흔한 실수

`<properties>` 에 `<netty.version>4.1.100.Final</netty.version>` 같은 걸 쓰는 방식은 **그 프로퍼티 이름이 부모 BOM에 실제로 정의돼 있을 때만** 동작한다. 이름을 틀리면 아무 효과 없이 조용히 무시되고, 취약점이 그대로 남은 채 "고쳤다"고 착각하게 된다.

- 부모 BOM(예: `spring-boot-dependencies`)이 그 프로퍼티를 정의한다고 **확실히 아는 경우에만** 프로퍼티 override 를 쓴다.
  `spring-boot-dependencies`(2.x·3.x 공통)가 정의하는 대표 프로퍼티: `netty.version`, `tomcat.version`, `jackson-bom.version`,
  `spring-framework.version`, `spring-security.version`, `reactor-bom.version`, `logback.version`, `log4j2.version`,
  `snakeyaml.version`, `thymeleaf.version`, `jetty.version`, `undertow.version`, `hibernate.version`, `micrometer.version`, `h2.version`.
  netty 계열 아티팩트(`io.netty:*`)는 전부 `netty.version` 하나가 관리하므로, 여러 netty 모듈이 걸려도 이 프로퍼티 한 줄로 해소한다.
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
