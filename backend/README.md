# cve-monitoring
CVE 취약점 정보 수집 및 보안 위험 모니터링 시스템

## 개발 환경

| 구분 | 내용 |
| --- | --- |
| Language | Java 17 |
| Framework | Spring Boot 3.3.4 |
| Build Tool | Maven (Maven Wrapper 포함, `./mvnw` \| `mvnw.cmd`) |
| Group / Artifact | `org.example` / `cve-monitoring` |

### 주요 의존성

- `spring-boot-starter-web` — REST API 서버
- `spring-boot-starter-tomcat` *(provided)* — 내장 서버 (외부 WAS 배포 시 제외)
- `lombok` — 보일러플레이트 코드 축소
- `spring-boot-starter-test` *(test)* — 단위/통합 테스트

### 빌드 & 실행

```bash
./mvnw clean package
./mvnw spring-boot:run
```

