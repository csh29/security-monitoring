# 알려진 오탐 패턴 (여기 해당하면 is_vulnerable: false)

의존성 스캐너가 이름 유사도로 잘못 매칭하는 대표 사례다. **아래에 정확히 해당할 때만** `false` 로 판정하고, reasoning에 "CVE 대상은 X, 설치된 것은 별개 산출물인 Y" 형태로 근거를 남긴다.

## 이름이 비슷하지만 별개 프로젝트

| CVE가 지목하는 것 | 혼동되는 별개 아티팩트 |
|---|---|
| `org.apache.logging.log4j:log4j-core` (2.x, Log4Shell 계열) | `log4j:log4j` (1.x — 코드베이스가 완전히 다름) |
| `log4j:log4j` (1.x 전용 CVE) | `log4j-core` 2.x |
| `commons-collections:commons-collections` (3.x) | `org.apache.commons:commons-collections4` |
| `org.apache.httpcomponents:httpclient` (4.x) | `org.apache.httpcomponents.client5:httpclient5` |
| `org.yaml:snakeyaml` 1.x 전용 CVE | `snakeyaml` 2.x |
| `xerces:xercesImpl` | JDK 내장 파서 |

## 같은 프로젝트의 다른 모듈

CVE가 모듈을 특정했을 때, 다음은 서로 다른 아티팩트다.

- Jackson: `jackson-databind` ↔ `jackson-core` ↔ `jackson-annotations` ↔ `jackson-dataformat-*`
  (역직렬화 가젯 계열 CVE는 대부분 `jackson-databind` 한정)
- Spring Framework: `spring-core` ↔ `spring-beans` ↔ `spring-web` ↔ `spring-webmvc` ↔ `spring-expression`
- Spring Security: `spring-security-core` ↔ `spring-security-web` ↔ `spring-security-oauth2-*`
- Netty: `netty-handler` ↔ `netty-codec-http` ↔ `netty-codec-http2` ↔ `netty-common`
- Tomcat: `tomcat-embed-core` ↔ `tomcat-embed-el` ↔ `tomcat-embed-websocket`
- Jetty: `jetty-server` ↔ `jetty-http` ↔ `jetty-servlets`

## false 로 내리면 안 되는 헷갈리는 케이스

반대 방향 실수도 흔하다. 아래는 **취약할 수 있으므로 배제하지 마라**.

- `bcprov-jdk15on` / `bcprov-jdk18on` / `bcprov-jdk15to18` — 같은 BouncyCastle 코드베이스의 JDK 타깃 변형이다. 둘 다 영향받는 경우가 많다.
- `org.json:json` 의 CVE와, 그것을 그대로 재배포한 셰이딩 아티팩트(`com.vaadin.external.google:android-json` 등) — 재배포본도 영향받을 수 있다.
- `spring-boot-starter-*` 같은 스타터는 코드가 없지만, **CVE 대상이 스타터가 관리하는 버전**일 수 있다. 스타터라서 무해하다고 단정하지 마라.
- groupId가 `javax.*` → `jakarta.*` 로 이관된 경우 — 같은 스펙 구현체다.

## 유지 방법

새 오탐을 확인할 때마다 위 표에 한 줄씩 추가한다. 이 파일이 이 시스템의 정확도를 결정한다.
