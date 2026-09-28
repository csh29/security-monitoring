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
| `ai/` | 파이썬 배치(`vuln_assessor.py`). 자바가 fire-and-forget으로 띄우고, 배치는 `/api/ai/**`를 직접 호출해 대기 중인 취약점을 스스로 가져가 판단 결과를 되돌려준다 |

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
├── dto/{ai,app,commoncode,nvd,osv,permission,program,scan,user,vulnerability}
├── repository   # JPA Repository
├── security     # @RequiresProgram + 이를 읽는 AuthorizationManager, ProgramAccessGuard
└── service/{ai,app,commoncode,git,maven,nvd,osv,permission,program,scan,user,vulnerability}
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
6. `AiAssessmentTriggerService.triggerAsync` → 파이썬 배치 기동(결과를 기다리지 않음)

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
4. **fix-plan** — "취약함"으로 확정된 CVE만 앱 단위로 모아 한 번에 pom.xml 수정안을 만든다.

AI에게 넘기는 근거도 마찬가지다. OSV에서 뽑은 `knownFixedVersions`가 있으면 AI가 설명 프로즈를
다시 해석해 유추하지 않도록 그 값을 최우선으로 쓰게 한다.

### 판정 결과가 이상할 때 보는 필드

`Vulnerability` 엔티티에 판정 근거가 남는다 — `nvdRangeVulnerable`(null이면 NVD로는 판단 불가),
`nvdMatchedRange`(실제 매치된 범위, 감사·디버깅용), `knownFixedVersions`(OSV가 준 수정 버전 후보).

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
  `SidebarModelAdvice`가 얹는다.

### 공통 자산

| 파일 | 역할 |
| --- | --- |
| `/css/common-ui.css` | `:root` 변수, `.app-shell`, `.btn`, `.panel-head` 등 페이지 뼈대 |
| `/css/grid.css` | `.grid` 공통 모양 |
| `/js/grid.js` | 컬럼 정의(`COLUMNS`)로 헤더·행·입력 셀까지 만드는 공통 그리드 렌더러 |
| `/js/common-code.js` | 공통코드로 select 옵션 채우기(그룹당 1회 캐시) |
| `/js/tabs.js` | 홈 화면 탭 |
| `fragments/loading-overlay.html` | 전역 스피너 + **CSRF 헤더를 붙이는 공통 fetch 래퍼** |

화면 코드에서 `fetch(...)`에 CSRF 헤더를 붙이는 부분을 찾아도 없다 — `loading-overlay.html`이
`window.fetch` 자체를 감싸서 전역으로 처리한다.

---

## 6. 보안 구조 (현재 동작 방식)

| 계층 | 어떻게 동작하는가 |
| --- | --- |
| 인증 | 폼 로그인 세션. `PUBLIC_URLS`(`/login`, 정적 자원, `/api/ai/**`, `/error`) 외에는 전부 로그인 필요 |
| 인가 진입점 | `SecurityConfig`는 `anyRequest().access(requiresProgramAuthorizationManager)` 한 줄뿐 — **URL 패턴 목록이 없다** |
| 프로그램 권한 | `RequiresProgramAuthorizationManager`가 요청을 처리할 컨트롤러(메서드 우선, 없으면 클래스)의 `@RequiresProgram`을 리플렉션으로 읽어 판단 |
| 어노테이션이 없으면 | **로그인만 하면 통과한다**(= 권한 미요구 API로 간주) |
| 예외 1건 | `CommonCodeController.getCodes`는 `@PreAuthorize` — `includeInactive`가 쿼리 파라미터라 메서드 단위 어노테이션으로 표현할 수 없기 때문 |
| CSRF | `/api/**` 포함 전체 검증(`CookieCsrfTokenRepository`). 화면 JS는 공통 fetch 래퍼가 헤더를 붙인다. **`/api/ai/**`만 `ignoringRequestMatchers`로 제외** — 세션 쿠키가 아니라 헤더 토큰으로 인증하는 배치 전용 경로라 CSRF 전제가 성립하지 않고, 빼지 않으면 배치의 POST가 전부 403이 된다 |
| 화면 접근 | `ViewController.programPage`가 화면 이름(`Program.programId`와 같은 값)으로 Program 등록 여부를 보고, 등록돼 있으면 `ProgramAccessGuard`로 권한을 확인한다. 등록되지 않은 화면은 고정 메뉴라 로그인만으로 열린다. 화면 이름은 `[a-z0-9-]+`만 허용(경로 조작 차단) |
| AI 배치 경로 | `/api/ai/**`는 세션 대신 `X-Internal-Token` 헤더로 자체 인증(`MessageDigest.isEqual`로 상수 시간 비교) |
| 스캔 대상 | 앱 관리에 등록된 `repoUrl/branch` 조합만 허용. 등록 자체는 `RepoUrlValidator`가 https + 허용 호스트만 통과시킨다 |
| 역할(`role`) | 공통코드 `ROLE` 그룹 값만 저장 가능. **다만 인가 판단에는 쓰이지 않는다** — 권한은 전적으로 `UserProgramPermission` 기준이고, `role`은 `CustomUserDetailsService`가 authority로 변환만 할 뿐 `hasRole(...)`을 보는 곳이 없다 |
| H2 콘솔 | `spring.h2.console.enabled=false`로 완전 비활성 |
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

즉 **컨트롤러·보안·화면에는 자동 테스트가 없다.** 그 영역의 변경을 분석할 때 "테스트가 통과했으니
안전하다"고 결론 내리지 않는다.

---

## 9. 프롬프트 자산

`ai/prompts/`에 시스템 프롬프트가 있고, 공통 규칙은 `ai/prompts/rules/*.md`로 쪼개져
`{{include: rules/xxx.md}}` 한 줄로 합쳐진다(`ai/prompt_rules.py`).

- `assess.system.md` — CVE 개별 판단
- `fix_plan.system.md` — pom.xml 수정안
- `rules/` — `false_positives.md`, `maven_strategy.md`, `version_matching.md`
