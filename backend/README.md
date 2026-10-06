# security-monitoring
보안취약점 모니터링 시스템 — 오픈소스 라이브러리 취약점(CVE)과 소스 코드 시큐어코딩 약점을 함께 점검·관리한다.

Git 저장소(Maven 프로젝트)를 clone 해서 의존성을 뽑고, OSV/NVD로 취약점을 조회한 뒤,
버전 범위로 판단할 수 없는 건만 AI로 판단해 pom.xml 수정안(fix-plan)까지 만들어 준다.
이와 별개 기능으로, 같은 저장소의 소스를 시큐어코딩 규칙(행안부 SW 보안약점 기준, Semgrep)으로 점검한다.

## 시스템 구성

| 모듈 | 역할 |
| --- | --- |
| `backend/` | Spring Boot 서버 + 화면(Thymeleaf). 스캔·판정·조회 전부 |
| `securecode/rules/` | 시큐어코딩 점검 규칙(Semgrep YAML)과 규칙별 테스트 예제. AI 없이 서버가 Semgrep으로 돌린다 |
| `securecode/trace-rules.yml` | MyBatis `${}` 연계 추적이 쓰는 시스템별 프레임워크 규칙(세션 값을 요청 맵에 덮어쓰는 어노테이션 등). 새 시스템을 점검할 때 항목을 추가한다 |
| `ai/` | 파이썬 AI 판단 배치(`vuln_assessor.py`). 판정·fix-plan·업그레이드 영향 분석(`claude-sonnet-5`)과 CVE 설명 한국어 요약(`claude-haiku-4-5`)을 한다. 영향 분석의 근거(릴리스 노트)는 `release_notes.py`가 AI 없이 모은다. 스캔 직후 AI 판단·fix-plan·설명 요약·영향 분석 대기 건이 있으면 서버가 띄우고, 배치는 `/api/ai/**`를 직접 호출해 대기 중인 취약점을 가져가 결과를 되돌려준다 |

## 개발 환경

| 구분 | 내용 |
| --- | --- |
| Language | Java 17 |
| Framework | Spring Boot 3.3.4 |
| Build Tool | Maven (Maven Wrapper 포함, `./mvnw` \| `mvnw.cmd`) |
| Group / Artifact | `org.example` / `security-monitoring` |
| 기본 패키지 | `com.sjinc.securitymonitor` |
| View | Thymeleaf (서버 렌더링) |
| DB | H2 파일 DB (`backend/data/cvemonitor.mv.db`, `ddl-auto=update`) |
| 인증 | Spring Security 폼 로그인 + 프로그램별 권한 |
| AI 배치 | Python (`py` 런처) + `anthropic`, `requests` |
| 코드 점검 | Semgrep 1.178.0 — 버전 고정 파일 `securecode/requirements.txt` |

### 주요 의존성

| 의존성 | 용도 |
| --- | --- |
| `spring-boot-starter-web` | REST API + 화면 서빙 |
| `spring-boot-starter-webflux` | 외부 API(NVD/OSV/Maven Central) 호출용 `WebClient` |
| `spring-boot-starter-data-jpa` | 엔티티 / Repository |
| `spring-boot-starter-security` | 로그인 및 접근 제어 |
| `spring-boot-starter-thymeleaf` | 화면 템플릿 |
| `h2` *(runtime)* | 파일 DB |
| `spring-boot-devtools` *(runtime, optional)* | 로컬 자동 재시작 |
| `spring-boot-starter-tomcat` *(provided)* | 내장 서버 (외부 WAS 배포 시 제외) |
| `maven-invoker` | 스캔 대상 프로젝트에서 `dependency:tree` 실행 |
| `maven-artifact` | NVD 버전 범위(cpeMatch)와 설치 버전 비교 — Maven 고유 버전 규칙(`.RELEASE`/`.Final` 등) 사용 |
| `jgit` | 스캔 대상 저장소 clone |
| `javaparser-core` | 코드 점검의 MyBatis `${}` 연계 추적 — 대상 저장소의 Java 소스를 빌드 없이 구문 분석 |
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
| `claude.api.key` | AI 판단 / fix-plan / 설명 요약 / 영향 분석 |
| `github.token` *(선택)* | 영향 분석이 GitHub Releases를 받을 때 쓰는 읽기 전용 토큰. 없으면 토큰 없이 부른다(IP당 시간당 60회) |
| `ai.internal.token` | 서버 ↔ 파이썬 배치 인증 토큰 |
| `ai.python.command` | 파이썬 실행 명령 (이 PC는 `py`) |
| `ai.assessor.script` | 배치 스크립트 경로 (`../ai/vuln_assessor.py`) |
| `ai.assessment.severities` | AI 판단 대상 등급 (기본 `HIGH,CRITICAL`) |
| `securecode.semgrep.command` *(선택)* | semgrep 실행 파일(기본 `semgrep`). PATH에 없으면 `ai.python.command` 파이썬의 Scripts 폴더에서 자동으로 찾는다 |
| `securecode.rules-dir` *(선택)* | 코드 점검 규칙 폴더(기본 `../securecode/rules`, backend/에서 띄우는 기준) |
| `securecode.timeout-seconds` *(선택)* | 코드 점검 1회 제한시간(기본 600초) |
| `securecode.trace-rules` *(선택)* | MyBatis `${}` 연계 추적 규칙 파일(기본 `../securecode/trace-rules.yml`) |
| `ai.auto-trigger.enabled` | 스캔 후 AI 배치 자동 실행의 초기값 — DB를 처음 만들 때만 쓰인다 (기본 `true`). 실행 중에는 공통코드 관리 화면 `AI_CONFIG`/`AUTO_TRIGGER` 사용여부로 재기동 없이 켜고 끈다 |

초기 관리자 계정은 DB를 처음 만들 때 무작위 비밀번호로 생성되며 **서버 로그에 한 번만 출력된다.**
DB는 `backend/data/`에 파일로 남아 재기동해도 유지된다. 처음부터 다시 시작하려면 서버를 끄고 `data` 폴더를 지운다
(초기 데이터와 관리자 비밀번호가 새로 만들어진다).

### AI 배치

서버가 스캔 직후 자동으로 띄우므로 따로 실행할 필요는 없다. 의존성만 미리 설치해 둔다.

```bash
py -m pip install -r ../ai/requirements.txt
```

> 이 PC에서 `python` / `python3`은 Microsoft Store 스텁이라 실행되지 않는다. 항상 `py`를 쓴다.

배치 로그는 `backend/ai-assessor.log`에 쌓인다.

릴리스 노트 수집기(`ai/release_notes.py`)의 테스트는 네트워크 없이 돈다.

```bash
cd ../ai
py -m unittest test_release_notes
```

### 코드 점검(Semgrep)

서버를 띄우는 PC마다 한 번 설치한다(화면만 쓰는 사람은 필요 없다). 버전이 고정돼 있어 PC마다 탐지 결과가 같다.
설정 파일은 손대지 않아도 된다 — PATH에 없으면 서버가 `py`의 Scripts 폴더에서 찾는다.

```bash
py -m pip install -r ../securecode/requirements.txt
```

서버는 기동할 때 Semgrep이 실행되는지, 고정 버전과 같은지 확인해 로그로 알린다(`Semgrep 1.178.0 확인 — 코드 점검 사용 가능`).
설치가 안 됐거나 버전이 다르면 WARN 로그에 설치 명령이 찍힌다. 기동 자체는 막지 않는다.

규칙을 고치면 규칙 옆의 예제 파일로 회귀 테스트를 돌린다(걸려야 할 줄은 `ruleid:`, 걸리면 안 되는 줄은 `ok:` 주석).

```bash
cd ../securecode
py test_rules.py
```

`semgrep --test .`로 한꺼번에 돌리면 Windows에서 Semgrep 설정 파일 잠금으로 실패한다 — 규칙마다 하나씩 돌리는 위 스크립트를 쓴다.

영향 분석에서 "근거 없음"으로 자주 뜨는 라이브러리는 `ai/release_note_sources.json`에 공식 문서 주소를 추가한다.

## 패키지 구조

`dto`와 `service`의 하위 패키지를 기능 단위로 통일했다.
이름만 보고 어떤 DTO가 어느 서비스에서 쓰이는지 알 수 있도록 하기 위함이다.

```
com.sjinc.securitymonitor
├── config                  # Spring 설정 (Security, WebClient, 초기 데이터)
├── controller              # REST API 엔드포인트
├── mvc                     # 화면(뷰) 반환 컨트롤러 + 사이드바·상단바 전역 모델
├── domain                  # 도메인 모델 (JPA 엔티티, VO)
├── security                # 프로그램 접근 권한 판정(ProgramAccessGuard)
├── dto
│   ├── ai                  # AI 판단/fix-plan 요청·응답 DTO
│   ├── app                 # 앱 관리 DTO
│   ├── comcd          # 공통코드 그룹/코드 DTO
│   ├── nvd                 # NVD CVE API 요청/응답 DTO
│   ├── osv                 # OSV API 요청/응답 DTO
│   ├── permission          # 사용자별 프로그램 권한 DTO
│   ├── program             # 프로그램(화면) 관리 DTO
│   ├── scan                # 스캔 요청/응답 DTO
│   ├── securecode          # 코드 점검(Semgrep 결과·탐지·처리여부) DTO
│   ├── user                # 사용자 관리 DTO
│   └── vulnerability       # 취약점 조회 API 응답 DTO
├── repository              # JPA Repository
└── service
    ├── ai                  # AI 배치 기동, fix-plan 저장/조회(AI로 보내는 pom.xml 비밀값 가림·되돌림)
    ├── app                 # 앱 관리
    ├── comcd          # 공통코드 그룹/코드
    ├── git                 # Git 저장소 clone
    ├── maven               # pom.xml 의존성 추출, Maven Central 실존 검증
    ├── nvd                 # NVD API 클라이언트, 버전 범위 판정
    ├── osv                 # OSV API 클라이언트, 수정 버전 해석
    ├── permission          # 사용자별 프로그램 권한
    ├── program             # 프로그램(화면) 관리
    ├── scan                # 스캔 오케스트레이션, 스캔 이력, 소스 사용 목록(import·설정 키) 추출
    ├── securecode          # 코드 점검: Semgrep 실행·결과 해석·코드 조각/지문·재점검 비교, 연계 추적(MyBatis ${}·위험 호출 지점)·추적 규칙 확인
    ├── user                # 사용자 관리, 인증
    └── vulnerability       # 취약점 조회/동기화/판정
```

> 이전에는 `dto.cve`에 NVD 응답과 OSV 응답 DTO가 섞여 있었고, `dto.git`에는 실제로는
> 스캔 기능 DTO(`ScanRequest`/`ScanResult`)가 들어 있어 패키지명과 역할이 맞지 않았다.

## 화면

화면은 `templates/program/<이름>.html` 하나만 추가하면 된다 — `ViewController`가 `/program/{*path}`
경로를 그대로 템플릿 이름으로 쓰므로 화면이 늘어도 컨트롤러를 고치지 않는다.
사이드바 메뉴는 고정 메뉴 + 로그인 사용자가 권한을 가진 프로그램이 자동으로 표시된다.
고정 메뉴는 홈 아래 두 기능 그룹(2뎁스, 접고 펼 수 있음)으로 나뉜다 — "라이브러리 취약점"(취약점 관리·취약점 조회·스캔 이력·조치안·리포트)과
"시큐어코딩"(코드 점검·코드 점검 결과). 그 아래가 권한 기반 "관리" 그룹이다(`mvc/FixedMenu`, `fragments/sidebar.html`).

공통 자산은 화면마다 다시 만들지 않고 아래를 쓴다.

| 파일 | 역할 |
| --- | --- |
| `/css/common-ui.css` | `:root` 변수, 레이아웃 셸, 버튼, 패널 헤더, 모달·상세 표(`.detail-list`), 상태 뱃지(`.badge`) |
| `/css/grid.css` | `.grid` 공통 모양 |
| `/js/grid.js` | 컬럼 정의로 헤더·행·입력 셀까지 만드는 공통 그리드 렌더러 |
| `/js/code-highlight.js` | 코드 조각 구문 강조(파일 확장자별, 외부 라이브러리 없음) |
| `/js/com-cd.js` | 공통코드로 select 옵션 채우기 (그룹당 1회 캐시) |
| `/js/tabs.js` | 홈 화면 탭 |
| `/js/hotkeys.js` | 공통 펑션키(F3 조회, F4 신규, F5 삭제, F9 저장, F12 초기화) — 버튼에 `data-hotkey` 속성으로 지정 |
| `/js/search-form.js` | 조회영역 공통 렌더러 — 필드 정의로 label + 입력을 만든다 |
| `fragments/page-toolbar.html` | 화면 첫 줄(프로그램명 + 권한에 따른 공통 버튼) |
| `/js/page-buttons.js` | 공통 버튼 핸들러 연결(`PageButtons.bind`) |
| `fragments/loading-overlay.html` | 전역 로딩 스피너 + CSRF 헤더를 붙이는 공통 fetch 래퍼 |

## 개발 지침

작업 규칙(개발 원칙, 판단 우선순위, 보안 불변 규칙, 작업 체크리스트)은 저장소 루트의
[`CLAUDE.md`](../CLAUDE.md)에 정리돼 있다.
