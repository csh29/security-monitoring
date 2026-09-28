# cve-monitoring
CVE 취약점 정보 수집 및 보안 위험 모니터링 시스템

Git 저장소(Maven 프로젝트)를 clone 해서 의존성을 뽑고, OSV/NVD로 취약점을 조회한 뒤,
버전 범위로 판단할 수 없는 건만 AI로 판단해 pom.xml 수정안(fix-plan)까지 만들어 준다.

## 시스템 구성

| 모듈 | 역할 |
| --- | --- |
| `backend/` | Spring Boot 서버 + 화면(Thymeleaf). 스캔·판정·조회 전부 |
| `ai/` | 파이썬 AI 판단 배치(`vuln_assessor.py`). 스캔 직후 AI 판단·fix-plan 대기 건이 있으면 서버가 띄우고, 배치는 `/api/ai/**`를 직접 호출해 대기 중인 취약점을 가져가 결과를 되돌려준다 |

## 개발 환경

| 구분 | 내용 |
| --- | --- |
| Language | Java 17 |
| Framework | Spring Boot 3.3.4 |
| Build Tool | Maven (Maven Wrapper 포함, `./mvnw` \| `mvnw.cmd`) |
| Group / Artifact | `org.example` / `cve-monitoring` |
| 기본 패키지 | `com.sjinc.cvemonitor` |
| View | Thymeleaf (서버 렌더링) |
| DB | H2 (in-memory, `ddl-auto=update`) |
| 인증 | Spring Security 폼 로그인 + 프로그램별 권한 |
| AI 배치 | Python (`py` 런처) + `anthropic`, `requests` |

### 주요 의존성

| 의존성 | 용도 |
| --- | --- |
| `spring-boot-starter-web` | REST API + 화면 서빙 |
| `spring-boot-starter-webflux` | 외부 API(NVD/OSV/Maven Central) 호출용 `WebClient` |
| `spring-boot-starter-data-jpa` | 엔티티 / Repository |
| `spring-boot-starter-security` | 로그인 및 접근 제어 |
| `spring-boot-starter-thymeleaf` | 화면 템플릿 |
| `h2` *(runtime)* | in-memory DB |
| `spring-boot-devtools` *(runtime, optional)* | 로컬 자동 재시작 |
| `spring-boot-starter-tomcat` *(provided)* | 내장 서버 (외부 WAS 배포 시 제외) |
| `maven-invoker` | 스캔 대상 프로젝트에서 `dependency:tree` 실행 |
| `maven-artifact` | NVD 버전 범위(cpeMatch)와 설치 버전 비교 — Maven 고유 버전 규칙(`.RELEASE`/`.Final` 등) 사용 |
| `jgit` | 스캔 대상 저장소 clone |
| `lombok` *(optional)* | 보일러플레이트 코드 축소 |
| `spring-boot-starter-test` *(test)* | JUnit 5 / Mockito / AssertJ |

## 빌드 & 실행

```bash
./mvnw clean package
```

```bash
./mvnw spring-boot:run
```

```bash
./mvnw test
```

Windows에서는 `mvnw.cmd`를 쓴다.

### 실행 전 설정

`src/main/resources/application.properties`는 API 키와 토큰이 들어 있어 **`.gitignore`에 올라가 있다.**
저장소를 새로 받았다면 아래 값을 직접 채워야 한다.

| 키 | 용도 |
| --- | --- |
| `nvd.api.key` | NVD CVE API |
| `git.access.token` / `git.user.name` | 스캔 대상 저장소 clone |
| `maven.home` | `dependency:tree` 실행용 Maven 홈 |
| `claude.api.key` | AI 판단 / fix-plan |
| `ai.internal.token` | 서버 ↔ 파이썬 배치 인증 토큰 |
| `ai.python.command` | 파이썬 실행 명령 (이 PC는 `py`) |
| `ai.assessor.script` | 배치 스크립트 경로 (`../ai/vuln_assessor.py`) |
| `ai.assessment.severities` | AI 판단 대상 등급 (기본 `HIGH,CRITICAL`) |

초기 관리자 계정은 기동할 때마다 무작위 비밀번호로 생성되며 **서버 로그에 한 번만 출력된다.**
(H2가 in-memory라 재기동 시 초기화된다.)

### AI 배치

서버가 스캔 직후 자동으로 띄우므로 따로 실행할 필요는 없다. 의존성만 미리 설치해 둔다.

```bash
py -m pip install -r ../ai/requirements.txt
```

> 이 PC에서 `python` / `python3`은 Microsoft Store 스텁이라 실행되지 않는다. 항상 `py`를 쓴다.

배치 로그는 `backend/ai-assessor.log`에 쌓인다.

## 패키지 구조

`dto`와 `service`의 하위 패키지를 기능 단위로 통일했다.
이름만 보고 어떤 DTO가 어느 서비스에서 쓰이는지 알 수 있도록 하기 위함이다.

```
com.sjinc.cvemonitor
├── config                  # Spring 설정 (Security, WebClient, 초기 데이터)
├── controller              # REST API 엔드포인트
├── mvc                     # 화면(뷰) 반환 컨트롤러 + 사이드바 전역 모델
├── domain                  # 도메인 모델 (JPA 엔티티, VO)
├── security                # 프로그램 접근 권한 판정(ProgramAccessGuard)
├── dto
│   ├── ai                  # AI 판단/fix-plan 요청·응답 DTO
│   ├── app                 # 앱 관리 DTO
│   ├── commoncode          # 공통코드 그룹/코드 DTO
│   ├── nvd                 # NVD CVE API 요청/응답 DTO
│   ├── osv                 # OSV API 요청/응답 DTO
│   ├── permission          # 사용자별 프로그램 권한 DTO
│   ├── program             # 프로그램(화면) 관리 DTO
│   ├── scan                # 스캔 요청/응답 DTO
│   ├── user                # 사용자 관리 DTO
│   └── vulnerability       # 취약점 조회 API 응답 DTO
├── repository              # JPA Repository
└── service
    ├── ai                  # AI 배치 기동, fix-plan 저장/조회
    ├── app                 # 앱 관리
    ├── commoncode          # 공통코드 그룹/코드
    ├── git                 # Git 저장소 clone
    ├── maven               # pom.xml 의존성 추출, Maven Central 실존 검증
    ├── nvd                 # NVD API 클라이언트, 버전 범위 판정
    ├── osv                 # OSV API 클라이언트, 수정 버전 해석
    ├── permission          # 사용자별 프로그램 권한
    ├── program             # 프로그램(화면) 관리
    ├── scan                # 스캔 오케스트레이션
    ├── user                # 사용자 관리, 인증
    └── vulnerability       # 취약점 조회/동기화/판정
```

> 이전에는 `dto.cve`에 NVD 응답과 OSV 응답 DTO가 섞여 있었고, `dto.git`에는 실제로는
> 스캔 기능 DTO(`ScanRequest`/`ScanResult`)가 들어 있어 패키지명과 역할이 맞지 않았다.

## 화면

화면은 `templates/program/<이름>.html` 하나만 추가하면 된다 — `ViewController`가 `/program/{*path}`
경로를 그대로 템플릿 이름으로 쓰므로 화면이 늘어도 컨트롤러를 고치지 않는다.
사이드바 메뉴는 고정 메뉴 + 로그인 사용자가 권한을 가진 프로그램이 자동으로 표시된다.

공통 자산은 화면마다 다시 만들지 않고 아래를 쓴다.

| 파일 | 역할 |
| --- | --- |
| `/css/common-ui.css` | `:root` 변수, 레이아웃 셸, 버튼, 패널 헤더 |
| `/css/grid.css` | `.grid` 공통 모양 |
| `/js/grid.js` | 컬럼 정의로 헤더·행·입력 셀까지 만드는 공통 그리드 렌더러 |
| `/js/common-code.js` | 공통코드로 select 옵션 채우기 (그룹당 1회 캐시) |
| `/js/tabs.js` | 홈 화면 탭 |
| `/js/hotkeys.js` | 공통 펑션키(F3 조회, F4 신규, F5 삭제, F9 저장, F12 초기화) — 버튼에 `data-hotkey` 속성으로 지정 |
| `/js/search-form.js` | 조회영역 공통 렌더러 — 필드 정의로 label + 입력을 만든다 |
| `fragments/page-toolbar.html` | 화면 첫 줄(프로그램명 + 권한에 따른 공통 버튼) |
| `/js/page-buttons.js` | 공통 버튼 핸들러 연결(`PageButtons.bind`) |
| `fragments/loading-overlay.html` | 전역 로딩 스피너 + CSRF 헤더를 붙이는 공통 fetch 래퍼 |

## 개발 지침

작업 규칙(개발 원칙, 판단 우선순위, 보안 불변 규칙, 작업 체크리스트)은 저장소 루트의
[`CLAUDE.md`](../CLAUDE.md)에 정리돼 있다.
