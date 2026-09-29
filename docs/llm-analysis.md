# llm-analysis.md — 분석용

**이 문서는 "지금 시스템이 어떻게 되어 있는가"(사실)만 적는다.**
코드를 읽고 파악·조사·설명·리뷰할 때 먼저 읽는다. 무엇을 어떻게 만들지(규범)는
[`llm-development.md`](llm-development.md)에 있다.

---

## 1. 무엇을 하는 시스템인가

Git 저장소(Maven 프로젝트)를 clone → 의존성 추출 → 취약점 DB 조회 → 판정 → pom.xml 수정안 생성
까지를 한 줄로 잇는 **CVE 취약점 수집·모니터링 시스템**이다.

```
[앱 등록]  →  [스캔]  →  [CVE 저장]  →  [자동/AI 판단]  →  [fix-plan 생성]  →  [화면 조회]
 app-mgmt     GitClone      NVD 보강         결정론 우선        pom.xml 수정안      Thymeleaf
              Maven tree    Vulnerability   → 애매할 때만 AI
              OSV 조회
```

| 모듈 | 역할 |
| --- | --- |
| `backend/` | Spring Boot 3.3.4 / Java 17 / Maven. 서버 + 화면(Thymeleaf) 전부 |
| `ai/` | 파이썬 배치(`vuln_assessor.py`). 스캔이 끝나면 할 일이 있을 때 서버가 띄우고(`AiAssessmentTriggerService`, 아래 4장), 사람이 직접 실행해도 된다. 어느 쪽이든 **배치가 드라이버다** — 배치가 `/api/ai/**`를 호출해 대기 중인 취약점·fix-plan을 스스로 가져가고 결과를 되돌려준다. 자바는 띄우기만 하고 결과를 기다리지 않는다 |

DB는 H2 in-memory(`ddl-auto=update`)다. **재기동하면 데이터가 사라지고** `DataInitializer`가
초기 데이터를 다시 심는다 — "DB에 있던 값이 없어졌다"는 현상을 버그로 오해하지 않는다.

---

## 2. 패키지 구조

`dto`와 `service`의 하위 패키지는 기능 단위로 이름을 맞춰 뒀다. 이름만 보고 어떤 DTO가 어느
서비스에서 쓰이는지 알 수 있다.

```
com.sjinc.cvemonitor
├── config       # Spring 설정 (SecurityConfig, WebClientConfig, DataInitializer)
├── controller   # REST API (@RestController) — 화면용 컨트롤러는 여기가 아니라 mvc/
├── mvc          # 화면(뷰) 반환 컨트롤러 + 전역 모델(ControllerAdvice)
├── domain       # JPA 엔티티
├── dto/{ai,app,comcd,nvd,osv,permission,program,scan,user,vulnerability}
├── repository   # JPA Repository
├── security     # @RequiresProgram + 이를 읽는 AuthorizationManager, ProgramAccessGuard, CsrfCookieFilter
└── service/{ai,app,comcd,git,maven,nvd,osv,permission,program,scan,user,vulnerability}
```

`controller`와 `mvc`가 나뉘어 있다 — **REST API를 찾을 때 `mvc`를 보면 안 되고, 화면 라우팅을
찾을 때 `controller`를 보면 안 된다.**

---

## 3. 스캔 파이프라인 (`ScanOrchestrationService`)

1. **등록 검증** — `repoUrl/branch`가 앱 관리에 등록된 조합인지 먼저 확인한다(미등록이면 예외).
2. `GitCloneService` → clone
3. `MavenDependencyExtractor` → `dependency:tree`로 의존성 + `broughtInBy`(전이 경로) 추출
4. `OsvClient.queryBatch` → 취약점 조회
5. `VulnerabilityService.upsertEntity` → NVD 보강 + 결정론 판정 + 저장
6. `resolveMissingVulnerabilities` → 이번 스캔에 안 걸린 기존 OPEN 건을 RESOLVED로 표시
7. `ScanSnapshot` 저장 (fix-plan이 나중에 참고할 pom.xml + tree 원문)
8. `triggerAiAssessmentIfNeeded` → AI 판단 대기(`getUnassessedVulnerabilities`)나 fix-plan 대기
   (`getPendingFixPlanTargets`)가 하나라도 있으면 `AiAssessmentTriggerService.triggerAsync()`로 파이썬
   배치를 백그라운드로 띄운다(fire-and-forget, 이미 떠 있으면 건너뜀). "새 CVE가 저장됐는가"가 아니라
   배치가 가져갈 대기열로 판단한다 — 새 CVE가 결정론 자동판정으로 끝나면 AI가 볼 게 없고, 새 CVE가
   없어도 스냅샷이 갱신되면 fix-plan은 다시 대기가 된다. 배치는 Claude API를 호출하므로(과금) 스캔마다
   비용이 생길 수 있다. 실행 상태는 `/api/ai/status`(`getStatus()`)로 본다.

### 5단계의 실패 처리

NVD 조회는 CVE 건수만큼 반복되는 외부 호출이라 한도 초과(429)·일시 장애가 실제로 난다.

- `NvdClient`가 호출 간격(`nvd.api.min-interval-ms`)을 지키고, 429/5xx/타임아웃은 지수 백오프로 재시도한다.
- 그래도 실패한 CVE는 **그 건만 건너뛰고 스캔은 계속된다.** 실패 건수는 `ScanResult.failedCveCount`로
  올라가 화면 알림에 표시된다 — "스캔은 성공했는데 일부가 조용히 빠진" 상태를 만들지 않기 위함이다.
- 실패한 CVE도 `currentKeys`에는 남으므로 6단계에서 잘못 RESOLVED 처리되지 않는다.

---

## 4. 판정이 일어나는 순서 — AI는 마지막 수단

이 시스템에서 AI 호출은 "판단할 근거가 코드로는 도저히 안 나올 때"만 일어난다.
**취약 판정 로직을 추적할 때는 반드시 이 순서대로 본다.**

1. **NVD 구조화 범위(cpeMatch)** — `NvdVersionRangeChecker`가 `maven-artifact`의 버전 비교
   규칙으로 직접 비교. 결과가 나오면 여기서 끝.
2. **OSV 구조화 범위 폴백** — NVD가 구조화 범위를 안 줬을 때 `OsvVersionRangeChecker`로 한 번 더.
   스캔 때 받아둔 `OsvVulnDetail`을 재사용하므로 OSV를 다시 호출하지 않는다.
3. **AI 판단** — 위 둘 다 판단 불가일 때만. 대상도 `ai.assessment.severities`(기본 HIGH/CRITICAL)로
   좁힌다.
4. **fix-plan** — "취약함"으로 확정된 CVE 중 **`ai.assessment.severities` 등급(기본 HIGH/CRITICAL)만** 앱 단위로
   모아 한 번에 pom.xml 수정안을 만든다(`findConfirmedVulnerable`의 등급 조건). 1·2번 자동판정은 등급과 무관하게
   모든 CVE에 돌아 LOW/MEDIUM에도 `aiVulnerable`을 매기므로, 등급 조건이 없으면 LOW/MEDIUM이 fix-plan에 대량으로
   섞인다(실제로 그랬다 — 출력 잘림·CVE 누락의 원인). 등급 밖 CVE는 fix-plan의 "제외됨" 메모로만 남는다.

AI에게 넘기는 근거도 마찬가지다. OSV에서 뽑은 `knownFixedVersions`가 있으면 AI가 설명 프로즈를
다시 해석해 유추하지 않도록 그 값을 최우선으로 쓰게 한다.

### 판정 결과가 이상할 때 보는 필드

`Vulnerability` 엔티티에 판정 근거가 남는다 — `nvdRangeVulnerable`(null이면 NVD로는 판단 불가),
`nvdMatchedRange`(실제 매치된 범위, 감사·디버깅용), `knownFixedVersions`(OSV가 준 수정 버전 후보).

### 처리여부(status)를 사람이 바꾼 경우

취약점 관리 화면에서 개발자가 분석 후 처리여부를 직접 바꿀 수 있다(`POST /api/vulnerabilities/status`,
고정 메뉴라 로그인만 필요). 수동으로 **처리완료(RESOLVED)** 한 건은 `statusManual=true`가 되어, 재스캔에서
CVE가 다시 발견돼도 `updateFromScan`이 OPEN으로 되돌리지 않는다 — 원래는 다시 발견되면 무조건 OPEN이었다.
설치 버전이 바뀌면 옛 버전 기준 판단이라 AI 판단처럼 해제되어 다시 OPEN이 된다. 수동으로 OPEN으로 되돌리면
다시 스캔 결과를 따른다. 판단 사유는 `remark`(비고)에 적고, 바꾼 사람은 `statusChangedBy`. 서버는 요청 중 실제로 달라진 항목만 반영한다 — 비고만 고친 행에 처리여부까지 다시 적용하면 스캔이 RESOLVED로 만든 건이 수동 처리로 굳기 때문이다. RESOLVED는 fix-plan 대상(`findConfirmedVulnerable`,
OPEN만)에서도 빠진다.

### 엔티티 키 주의

`Vulnerability`는 `(app_id, cve_id, group_id, artifact_id)` 복합 유니크다. 같은 CVE가 한 앱 안의
서로 다른 아티팩트에 동시에 걸리는 경우가 실제로 있어서(micrometer-core / micrometer-registry-prometheus),
`group_id`/`artifact_id`가 키에 들어가 있다. **CVE 단위로 유일하다고 가정하고 읽으면 틀린다.**

---

## 5. 화면 레이어

- 모든 화면은 `templates/program/<이름>.html` 하나로 존재한다. `ViewController`의
  `/program/{*path}`가 경로를 그대로 템플릿 이름으로 쓴다 — **화면별 매핑 코드를 찾아도 없다.**
  화면 이름이 `Program.programId`와 같은 값이라, 같은 자리에서 "Program에 등록된 화면이면
  그 권한이 있어야 열린다"까지 함께 판단한다(6장).
- 사이드바는 고정 메뉴 + `extraPrograms`(로그인 사용자가 권한을 가진 추가 프로그램)를
  `SidebarModelAdvice`가 얹는다. 추가 프로그램은 전부 관리성 화면이라 접었다 폈다 하는 **"관리" 그룹 하나**
  아래에 들어간다(`sidebar.html`, 하나도 없으면 그룹 자체를 안 그림). 접을 때 링크는 숨기기만 하므로
  `tabs.js`의 `.nav a` 목록은 그대로이고, 그룹 안 화면이 활성화되면 그룹이 펼쳐진다. 접힘 상태는
  localStorage에만 기억한다. 프로그램마다 다른 상위 메뉴를 두는 구조(Program에 상위 메뉴 컬럼)는 아직 없다.
  화면 뼈대는 상단바가 전체 폭 첫 줄(좌상단 햄버거·로고·앱 이름 포함, `topbar.html`), 그 아래가 사이드바 | 본문이다.
  사이드바는 상단바의 햄버거 버튼으로 접을 수 있다(접기 스크립트도 `topbar.html`) — `.app-shell`에 `is-sidebar-collapsed`를 붙여 `--left-w`를
  64px로 바꾸고 메뉴 이름(`.nav-label`)을 숨긴다(이름은 `title` 툴팁). 이 상태도 localStorage(`sidebar.collapsed`)에만 기억한다.
- 상단바(`fragments/topbar.html`) 우측은 로그인 사용자 `사용자명(아이디)` · 비밀번호 변경 · 로그아웃이다. 표시 문구는
  `TopbarModelAdvice`가 `loginUserLabel`로 얹는다. 비밀번호 변경 모달은 topbar 조각 안에 있고 `POST /api/users/me/password`
  (본인만 — 대상은 Principal, 현재 비밀번호 재확인, `@RequiresProgram` 없음)를 부른다. 탭(iframe) 안에서는 상단바가 숨겨진다.

### 공통 자산

| 파일 | 역할 |
| --- | --- |
| `/css/common-ui.css` | `:root` 변수, `.app-shell`, `.btn`, `.panel-head`, `.page-toolbar`, 모달(`.modal-backdrop`+`.open` / `.modal` / `.modal-actions`) 등 페이지 뼈대. 화면 공통 버튼은 항상 우측 상단 — 제목과 한 줄이면 `.panel-head`, 조회조건 영역이 있으면 그 위에 `.page-toolbar` |
| `/css/grid.css` | `.grid` 공통 모양. 헤더 높이(45px)와 본문 행 높이(32px)를 모든 그리드에서 고정한다 — 화면 `<style>`에서 행 높이를 덮어쓰지 않는다. 헤더는 `position:sticky`라 세로 스크롤 때 고정된다 |
| `/js/grid.js` | 컬럼 정의(`COLUMNS`)로 헤더·행·입력 셀까지 만드는 공통 그리드 렌더러. `renderHeader`가 tbody의 첫 안내 행("조회 중입니다...", colspan 자동)도 넣으므로 템플릿의 `<tbody>`는 비워 둔다. 행 데이터는 `getRows`/`getRow`(원본 row + 입력 셀 현재 값, `_rowIndex`/`_isNew`/`_selected`)로 읽고 `onRowClick(tr, row)`도 같은 값을 받는다. select 컬럼에 `display(value, label, row)`를 주면 평소엔 그 결과(뱃지 등)를 보여주고 셀을 누를 때만 select로 바뀐다(취약점 관리 처리여부). 또 table을 `.grid-scroll`로 감싸고 숫자 `width`를 최소 폭으로도 적용해, 화면보다 넓으면 가로 스크롤이 생긴다. `.grid-scroll`의 세로 한도(`max-height`)는 grid.js가 "그 영역 시작 위치부터 화면 아래 끝까지"로 계산해 넣어(헤더·행을 그릴 때, 창 크기 변경 때), 행이 많으면 페이지가 아니라 그리드 본문만 스크롤된다(최소 200px). 화면이 스크롤 영역을 직접 둔 경우(`.grid-wrap`, 취약점 관리)는 감싸지 않는다 |
| `/js/com-cd.js` | 공통코드로 select 옵션 채우기(그룹당 1회 캐시) |
| `/js/tabs.js` | 홈 화면 탭 |
| `/js/hotkeys.js` | 공통 펑션키 F3 조회 / F4 신규 / F5 삭제 / F9 저장 / F12 초기화. 버튼에 `data-hotkey="F3"`만 붙이면 되고, 버튼 글자 뒤 `[F3]` 표기도 이 파일이 자동으로 붙인다. `loading-overlay.html`이 싣는다 |
| `/js/search-form.js` | 조회영역 공통 렌더러 `SearchForm.render(container, fields, {onSearch})` → `values()`/`reset()`/`field(id)`/`matches(row)`/`ready`. `matches(row)`는 전체 목록을 받아 조회조건을 화면에서 거르는 화면(프로그램·사용자·공통코드 관리, 취약점 조회)이 쓴다 — text 필드마다 `row[field.id]` 부분 일치(대소문자 무시). 화면은 `<section class="search-row" id="searchArea">`만 두고 label/input 마크업을 직접 쓰지 않는다 |
| `fragments/page-toolbar.html` | 화면 첫 줄 — 좌상단 프로그램명 + 우측 상단 공통 버튼. 값(`programNm`, `pageButtons`)은 `ViewController`가 넣는다. 버튼은 마크업에 쓰지 않는다(아래 "화면 공통 버튼" 참고) |
| `/js/page-buttons.js` | `PageButtons.bind({ btnSave: fn })` — 권한 때문에 안 그려진 버튼은 건너뛰고 핸들러를 건다. `loading-overlay.html`이 싣는다 |
| `fragments/loading-overlay.html` | 전역 스피너 + **CSRF 헤더를 붙이는 공통 fetch 래퍼** + `hotkeys.js` 로드 |

화면 코드에서 `fetch(...)`에 CSRF 헤더를 붙이는 부분을 찾아도 없다 — `loading-overlay.html`이
`window.fetch` 자체를 감싸서 전역으로 처리한다.

---

## 6. 보안 구조 (현재 동작 방식)

| 계층 | 어떻게 동작하는가 |
| --- | --- |
| 인증 | 폼 로그인 세션. `PUBLIC_URLS`(`/login`, 정적 자원, `/api/ai/**`, `/error`) 외에는 전부 로그인 필요 |
| 비로그인·세션 만료 | `RequiresProgramAuthorizationManager`가 **익명 토큰도 거부**한다(`isAuthenticated()`는 익명에게도 true라 그것만 보면 비로그인 사용자가 통과한다 — 실제로 그랬다). 거부된 요청은 화면이면 `/login`으로 302, `/api/**`면 **401**(`SecurityConfig.authenticationEntryPoint`). 401은 공통 fetch 래퍼(`loading-overlay.html`)가 받아 창 전체(`window.top`)를 로그인 페이지로 보내고, 화면의 then/catch는 실행되지 않는다. 탭(iframe) 안에서 로그인 페이지가 뜨면 `login.html`이 창 전체로 옮긴다 |
| 인가 진입점 | `SecurityConfig`는 `anyRequest().access(requiresProgramAuthorizationManager)` 한 줄뿐 — **URL 패턴 목록이 없다** |
| 프로그램 권한 | `RequiresProgramAuthorizationManager`가 요청을 처리할 컨트롤러(메서드 우선, 없으면 클래스)의 `@RequiresProgram`을 리플렉션으로 읽어 판단. 값을 여러 개 주면 그중 하나만 권한이 있어도 통과한다 — 예: `ComCdGroupController`는 클래스에 `com-cd-master-mng`(그룹 등록·수정·삭제)를, 목록 조회 `getGroups`에는 두 공통코드 화면(`com-cd-master-mng`, `com-cd-mng`)을 함께 걸었다 |
| 어노테이션이 없으면 | **로그인만 하면 통과한다**(= 권한 미요구 API로 간주) |
| 예외 1건 | `ComCdController.getCodes`는 `@PreAuthorize` — `includeInactive`가 쿼리 파라미터라 메서드 단위 어노테이션으로 표현할 수 없기 때문 |
| CSRF | `/api/**` 포함 전체 검증(`CookieCsrfTokenRepository`). 화면 JS는 공통 fetch 래퍼가 헤더를 붙인다. 래퍼는 `XSRF-TOKEN` 쿠키를 읽으므로, `CsrfCookieFilter`가 요청마다 토큰을 화면 렌더링 전에 먼저 읽어 쿠키를 응답 초반에 심는다 — 없으면 로그인(토큰 폐기) 직후 첫 화면에서 쿠키가 응답 버퍼 초과로 버려져 첫 POST가 403이 났다(실제로 그랬다). **`/api/ai/**`만 `ignoringRequestMatchers`로 제외** — 세션 쿠키가 아니라 헤더 토큰으로 인증하는 배치 전용 경로라 CSRF 전제가 성립하지 않고, 빼지 않으면 배치의 POST가 전부 403이 된다 |
| 화면 공통 버튼 | 툴바 버튼 = **프로그램이 쓰는 버튼**(`programs`의 `search_yn`~`reset_yn`, 기타는 `etc1_nm`~`etc5_nm`에 이름이 있으면) **∩ 사용자에게 허용된 버튼**(`user_program_permissions`의 `search_yn`~`etc5_yn`). `ProgramService.getPageButtons`가 `ProgramButton` 순서로 만든다. 고정 메뉴는 `mvc/FixedMenu`에 버튼이 고정돼 있다. **화면 표시만 막는다** — API는 여전히 `@RequiresProgram`(프로그램 단위)만 본다 |
| 화면 접근 | `ViewController.programPage`가 화면 이름(`Program.programId`와 같은 값)으로 Program 등록 여부를 보고, 등록돼 있으면 `ProgramAccessGuard`로 권한을 확인한다. 등록되지 않은 화면은 고정 메뉴라 로그인만으로 열린다. 화면 이름은 `[a-z0-9-]+`만 허용(경로 조작 차단) |
| AI 배치 경로 | `/api/ai/**`는 세션 대신 `X-Internal-Token` 헤더로 자체 인증(`MessageDigest.isEqual`로 상수 시간 비교) |
| 스캔 대상 | 앱 관리에 등록된 `repoUrl/branch` 조합만 허용. 등록 자체는 `RepoUrlValidator`가 https + 허용 호스트만 통과시킨다 |
| 역할(`role`) | 공통코드 `ROLE` 그룹 값만 저장 가능. **다만 인가 판단에는 쓰이지 않는다** — 권한은 전적으로 `UserProgramPermission` 기준이고, `role`은 `CustomUserDetailsService`가 authority로 변환만 할 뿐 `hasRole(...)`을 보는 곳이 없다 |
| H2 콘솔 | 기본 `spring.h2.console.enabled=false`. 로컬에서 켜면 앱 로그인은 여전히 필요하고, `/h2-console/**`만 CSRF 검증에서 빠진다(`SecurityConfig`가 이 설정값을 읽어 켰을 때만 제외) |
| 초기 관리자 | 기동할 때마다 무작위 비밀번호 생성 → 서버 로그에 1회만 출력 |

> 권한을 추적할 때 `SecurityConfig`에서 URL 표를 찾지 말고 **해당 컨트롤러의 `@RequiresProgram`을
> 본다.** 반대로 "이 API가 왜 아무나 접근되지?"는 대개 어노테이션 누락이다.

---

## 7. 설정 키

`application*.properties`는 `.gitignore`에 올라가 있어 저장소에 없다. 값이 아니라 **키와 용도**만
여기 적는다.

| 키 | 용도 |
| --- | --- |
| `nvd.api.key` | NVD CVE API |
| `nvd.api.min-interval-ms` | NVD 호출 사이 최소 간격(기본 700). NVD는 키가 있어도 30초당 50회가 상한이라 간격을 두지 않으면 반드시 429를 맞는다 |
| `nvd.api.max-retries` | NVD 429/5xx 재시도 횟수(기본 3) |
| `nvd.api.timeout-seconds` | NVD 호출 1회 타임아웃(기본 20) |
| `git.access.token` / `git.user.name` | 스캔 대상 저장소 clone |
| `maven.home` | `dependency:tree` 실행용 Maven 홈 |
| `claude.api.key` | AI 판단 / fix-plan |
| `ai.internal.token` | 자바 ↔ 파이썬 배치 인증 (`CVE_MONITOR_AI_TOKEN`과 같은 값) |
| `ai.python.command` | 파이썬 실행 명령 (이 PC는 `py`) |
| `ai.assessor.script` | 배치 스크립트 경로 (`../ai/vuln_assessor.py`) |
| `ai.assessment.severities` | AI 판단 대상 등급 (기본 `HIGH,CRITICAL`) |
| `scan.allowed-repo-hosts` | 앱 등록을 허용할 저장소 호스트 목록(쉼표 구분, 기본 `git.sejung.co.kr`). 다른 호스트를 쓰게 되면 여기서 늘린다 |

AI 배치 실행 로그는 `backend/ai-assessor.log`에 쌓인다(gitignore 대상).

---

## 8. 테스트 현황

Spring 컨텍스트 없이 도는 **순수 단위 테스트**뿐이다(JUnit 5 + Mockito + AssertJ).
`@SpringBootTest`는 쓰지 않는다.

- `NvdVersionRangeCheckerTest`, `OsvVersionRangeCheckerTest`, `OsvFixVersionResolverTest`
  — 버전 범위 / 수정 버전 판정 로직
- `VulnerabilityServiceTest` — upsert·AI 판단 반영 흐름
- `VulnerabilityTest` — 엔티티 규칙
- `RepoUrlValidatorTest` — 앱 등록 저장소 URL 허용/거부 판정
- `UserServiceTest` — 본인 비밀번호 변경 검증(현재 비밀번호 확인, 빈 값·동일 값 거부)

즉 **컨트롤러·보안·화면에는 자동 테스트가 없다.** 그 영역의 변경을 분석할 때 "테스트가 통과했으니
안전하다"고 결론 내리지 않는다.

---

## 9. 프롬프트 자산

`ai/prompts/`에 시스템 프롬프트가 있고, 공통 규칙은 `ai/prompts/rules/*.md`로 쪼개져
`{{include: rules/xxx.md}}` 한 줄로 합쳐진다(`ai/prompt_rules.py`).

- `assess.system.md` — CVE 개별 판단
- `fix_plan.system.md` — pom.xml 수정안
- `rules/` — `false_positives.md`, `maven_strategy.md`, `version_matching.md`
