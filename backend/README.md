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

## 패키지 구조

`dto`와 `service`의 하위 패키지를 기능 단위(`nvd` / `osv` / `scan` / `vulnerability`)로 통일했다.
이름만 보고 어떤 DTO가 어느 서비스에서 쓰이는지 알 수 있도록 하기 위함이다.

```
com.sjinc.cvemonitor
├── config                  # Spring 설정 (WebClient 등)
├── controller              # REST API 엔드포인트
├── domain                  # 도메인 모델 (JPA 엔티티, VO)
├── dto
│   ├── nvd                 # NVD CVE API 요청/응답 DTO
│   ├── osv                 # OSV API 요청/응답 DTO
│   ├── scan                # 스캔 요청/응답 DTO
│   └── vulnerability       # 취약점 조회 API 응답 DTO
├── repository              # JPA Repository
└── service
    ├── git                 # Git 저장소 clone
    ├── maven               # pom.xml 의존성 추출
    ├── nvd                 # NVD API 클라이언트
    ├── osv                 # OSV API 클라이언트
    ├── scan                # 스캔 오케스트레이션
    └── vulnerability       # 취약점 조회/동기화
```

> 이전에는 `dto.cve`에 NVD 응답과 OSV 응답 DTO가 섞여 있었고, `dto.git`에는 실제로는
> 스캔 기능 DTO(`ScanRequest`/`ScanResult`)가 들어 있어 패키지명과 역할이 맞지 않았다.

