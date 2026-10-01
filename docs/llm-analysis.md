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
| `ai/` | 파이썬 배치(`vuln_assessor.py`). 스캔이 끝나면 할 일이 있을 때 서버가 띄우고(`AiAssessmentTriggerService`, 아래 4장), 사람이 직접 실행해도 된다. 어느 쪽이든 **배치가 드라이버다** — 배치가 `/api/ai/**`를 호출해 대기 중인 취약점·fix-plan·설명 요약·영향 분석을 스스로 가져가고 결과를 되돌려준다. 자바는 띄우기만 하고 결과를 기다리지 않는다 |

DB는 H2 **파일 DB**(`jdbc:h2:file:./data/cvemonitor` → 서버를 띄운 `backend/data/cvemonitor.mv.db`, `ddl-auto=update`)다.
재기동해도 데이터가 남는다. `DataInitializer`는 **DB가 비어 있을 때(사용자 0명) 한 번만** 초기 데이터를 심으므로,
**거기에 심을 데이터를 새로 추가해도 이미 만들어진 DB에는 들어가지 않는다** — 새로 시작하려면 서버를 끄고 `data` 폴더를 지운다.
초기 관리자 비밀번호도 DB를 처음 만들 때 한 번만 로그에 찍힌다. 같은 DB 파일은 한 프로세스만 열 수 있어서 서버를 두 개 띄우거나
서버가 켜진 채 다른 도구로 열면 잠금 오류가 난다. 예전엔 메모리 DB라 재기동마다 사람이 남긴 처리여부·비고·요약이 사라지고 요약이 다시 과금됐다.
초기 데이터에 샘플 앱(CRM_BACK, CRM_BATCH)은 있지만 취약점은 없다 — 취약점 화면은 스캔을 한 번 돌려야 채워진다. 이미 만들어진 DB에 예전에 심은 샘플 취약점(설명이 `[샘플]`로 시작)이 남아 있을 수 있다.

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
   — 이어서 `ScanHistoryService.succeed`로 이번 회차의 스캔 이력을 완료 처리한다(아래 "스캔 이력")
8. `triggerAiAssessmentIfNeeded` → 먼저 자동 실행 스위치(공통코드 `AI_CONFIG`/`AUTO_TRIGGER`의 사용여부)를 보고 꺼져 있으면 바로 끝낸다. 켜져 있으면 AI 판단 대기(`getUnassessedVulnerabilities`), fix-plan 대기
   (`getPendingFixPlanTargets`), 설명 요약 대기(`CveSummaryService.getPendingSummaryTargets`), 영향 분석 대기(`UpgradeImpactService.getPendingTargets`)가 하나라도 있으면 `AiAssessmentTriggerService.triggerAsync()`로 파이썬
   배치를 백그라운드로 띄운다(fire-and-forget, 이미 떠 있으면 건너뜀). "새 CVE가 저장됐는가"가 아니라
   배치가 가져갈 대기열로 판단한다 — 새 CVE가 결정론 자동판정으로 끝나면 AI가 볼 게 없고, 새 CVE가
   없어도 스냅샷이 갱신되면 fix-plan은 다시 대기가 된다. 배치는 Claude API를 호출하므로(과금) 스캔마다
   비용이 생길 수 있다. 실행 상태는 `/api/ai/status`(`getStatus()`)로 본다.

### 스캔 이력 (`ScanHistory`, `ScanHistoryService`)

`ScanSnapshot`은 앱당 최신 하나를 덮어쓰므로 "언제 돌았고 무엇이 바뀌었나"는 `scan_histories`에 따로 쌓는다.

- 1단계 등록 검증을 **통과한 스캔만** 기록한다(미등록 저장소 요청은 이력이 없다). clone 전에 `RUNNING`으로 먼저 저장하고,
  끝나면 `SUCCESS`(의존성 수·발견·신규·해결·조회실패 건수) 또는 `FAILED`(오류 문구)로 바꾼다. 서버가 도중에 죽으면 `RUNNING`으로 남는다.
- **신규 건수** = 스캔 전 OPEN 키 집합에 없고 스캔 후 OPEN 키 집합에 있는 것(`countNewlyOpened`, 키는 `cveId|groupId:artifactId`).
  처음 발견된 건과 해결됐다가 다시 걸린 건이 모두 들어간다. 수동 RESOLVED 건은 재발견돼도 OPEN이 안 되므로 안 들어간다.
  **해결 건수** = `resolveMissingVulnerabilities`의 반환값(RESOLVED로 바꾼 건수).
- 오류 문구는 `IllegalArgumentException`만 메시지를 그대로 쓰고, 나머지는 예외 종류만 남긴다(`ScanController.handleScanError`와 같은 이유 — 내부 경로 노출).
- 앱을 FK로 참조하지 않고 appId·시스템명·저장소·브랜치를 값으로 복사한다 — FK면 이력이 생긴 앱을 앱 관리에서 못 지운다.
- 이력 기록이 실패해도 스캔은 실패시키지 않는다(로그만). 스캔 실행자는 `ScanController`가 Principal에서 넘긴다.
- 조회: `GET /api/scan-histories?appId=`(생략 시 전체, 최신순 최대 500건). 화면은 고정 메뉴 `scan-history`라 둘 다 로그인만 필요하다.

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

fix-plan 응답에는 수정된 pom.xml과 함께 **바꾼 버전 값 목록**(`changes`: 좌표·프로퍼티명·from·to·via
`PARENT/BOM/PROPERTY/DIRECT`)이 온다. 자바가 `FixPlanChange`(`fix_plan_changes`)로 저장하면서 점프 폭
(`VersionJump`: PATCH/MINOR/MAJOR/UNKNOWN)을 `VersionJumpClassifier`로 붙인다 — 순서는 `ComparableVersion`, 어느 자리가
바뀌었는지는 숫자 조각으로 본다. 낮추거나 그대로 둔 변경·해석 불가 버전은 UNKNOWN이다. 형식이 틀린 항목(좌표가
`g:a`가 아님, 버전 누락, 정해지지 않은 via)은 **그 항목만 버리고** 수정안은 저장한다(`FixPlanService.validChanges`, 버린 건수는 로그).
`changes` 필드가 생기기 전 배치가 보낸 요청(필드 없음)도 빈 목록으로 받는다. `GET /api/fix-plans/{appId}` 응답에 `changes`가 실린다.
이 목록이 아래 영향 분석(stage 4)의 입력이다.

AI에게 넘기는 근거도 마찬가지다. OSV에서 뽑은 `knownFixedVersions`가 있으면 AI가 설명 프로즈를
다시 해석해 유추하지 않도록 그 값을 최우선으로 쓰게 한다.

### 설명 요약 — 판정과 별개인 3단계

배치의 마지막 단계(stage 3)가 NVD 영어 설명을 한국어 2~3문장으로 요약해 `CveSummary`에 저장한다(`prompts/summarize.system.md`).
판정이 아니라 화면(취약점 관리 상세보기)에서 읽기 위한 것이라 판정과 조건이 전부 다르다.

- **모델:** `SUMMARY_MODEL = claude-haiku-4-5` (판정·fix-plan은 `MODEL`). effort·thinking 없이 돈다.
- **묶음 요청:** `SUMMARY_BATCH_SIZE`(10)건을 한 요청으로 보내고 structured output(`SUMMARY_SCHEMA`, `{cve_id, summary}` 배열)으로 받아 CVE별로 나눠 저장한다. 건마다 보내면 요약 규칙(약 500토큰)이 건수만큼 반복돼 입력의 60% 이상이었다. 요청이 실패하면 그 묶음 전체가, 응답에서 빠진 CVE는 그 건만 실패로 남고 다음 배치에서 다시 대기가 된다. 요청하지 않은 CVE ID로 온 요약은 버린다.
- **대상:** 등급·판정·상태와 무관하게 설명이 있는 모든 CVE. **단위는 CVE ID** — `Vulnerability` 행이 아니다(같은 CVE가 여러 행이라
  행마다 두면 같은 문장을 여러 번 요약해 과금된다).
- **재요약 기준:** 요약한 설명의 SHA-256(`descriptionHash`)과 현재 설명의 해시가 다를 때만. `nvdLastModified`는 설명과 무관한
  NVD 수정에도 바뀌어서 쓰지 않는다. 같은 CVE의 행마다 설명이 다르면 `nvdLastModified`가 가장 최근인 행의 설명을 쓴다.
- **API:** `GET /api/ai/summaries/pending`, `POST /api/ai/summaries`(해시는 pending에서 받은 값을 그대로 되돌려준다).
  빈 요약·1000자 초과·미등록 CVE는 400으로 거절한다.
- 화면 조회(`VulnerabilityService.getVulnerabilities`)가 CVE ID로 요약을 붙여 `VulnerabilityInfo.descriptionSummary`로 내려준다.

### 업그레이드 영향 분석 — stage 4

fix-plan이 올리는 라이브러리마다 "올리면 무엇이 깨지나"를 릴리스 노트 근거로 정리한다. 판정·fix-plan 뒤에 돈다.

- **대상:** `fix_plan_changes` 중 점프가 `MINOR`/`MAJOR`인 것. PATCH는 하위 호환이 원칙이라, UNKNOWN은 사람이 fix-plan을 다시
  봐야 하는 건이라 대상이 아니다. **단위는 `(좌표, from, to)`** — `UpgradeImpact`(`upgrade_impacts`)에 하나만 두고 여러 앱이 공유한다
  (같은 Spring Boot 업그레이드를 앱마다 분석하면 같은 릴리스 노트로 앱 수만큼 과금된다).
- **근거 수집(`ai/release_notes.py`, AI 없음):** ① 규칙 파일 `ai/release_note_sources.json`(groupId → 공식 문서 URL. Spring Boot
  위키 Release Notes·Migration Guide, Tomcat changelog, Hibernate·Jackson·Netty 문서) ② ①이 없을 때만 Maven Central POM의 `<scm>`(부모 POM까지)
  → GitHub/GitLab Releases, 없으면 저장소 CHANGELOG ③ 앞에서 아무것도 없을 때만 `<issueManagement>`의 JIRA 해결 이슈 목록.
  **①을 찾으면 ②를 읽지 않는다** — Spring Boot 3.1.5→3.2.12 실측에서 GitHub 패치 노트 12건(대부분 버그 수정 목록)이 근거의 3/4(12만 자 중 9만 자)을
  차지했다. 빼면 패치 노트의 "Noteworthy"(동반 라이브러리 버전 변경 알림)는 못 보므로 그 사실을 `note`에 남긴다.
  GitHub Releases는 100개 미만 페이지에서 멈춘다(빈 다음 페이지 호출로 한도를 쓰지 않게).
  - **범위:** from 초과 ~ to 이하. 라인이 바뀌면 옛 라인의 뒤늦은 패치(3.1.5→3.2.12에서 3.1.6~)는 뺀다. 마일스톤·RC는 빼되,
    새 라인 x.y.0의 사전 릴리스는 넣는다(Tomcat 10.1은 breaking change가 10.1.0-M* 노트에만 있다).
  - **한 문서에 여러 버전(CHANGELOG, Tomcat changelog):** 버전이 적힌 제목 줄로 절을 나눠 범위 안 절만 남기고, 새 라인 x.y.0 절을 앞에 둔다.
    버전 없는 소제목("### Bug Fixes")은 절 경계가 아니다. 범위 안 절이 없으면 문서를 통째로 넘기지 않는다.
  - **GitHub 위키는 raw 주소가 404**라 위키 페이지 HTML에서 `#wiki-body`만 읽는다(`container_id`).
  - **상한:** 문서당 8만 자, 합계 12만 자. 넘으면 문서는 앞부분만, 합계는 뒤쪽 문서부터 빼고 `note`에 남긴다.
  - GitHub API는 `GITHUB_TOKEN`(서버 설정 `github.token`, 선택)이 있으면 쓰고 없으면 토큰 없이 부른다(IP당 시간당 60회).
- **상태:** 근거가 있으면 AI 분석 후 `ANALYZED`. 근거를 못 찾으면 **AI를 부르지 않고** `NO_SOURCE`(다시 대기로 잡지 않는다 — 규칙 파일에
  추가한 뒤 다시 돌리려면 그 행을 지운다). 호출 한도·네트워크 같은 일시 오류로 근거가 없으면 `FETCH_FAILED`(다음 배치에서 다시 대기).
  AI 호출·저장이 실패하면 저장하지 않으므로 역시 다음 배치에서 다시 대기가 된다.
- **AI(`prompts/impact.system.md`, `MODEL`):** 근거 문서에 없는 내용을 쓰지 않게 하고, breaking change마다 근거 문서 URL을 `source_url`로 달게 한다.
- **자바의 정규화(`UpgradeImpactService.normalize`):** 출처가 근거 목록에 없는 breaking change는 버린다(파이썬도 거른다). 메이저 점프는 risk를
  `HIGH`로 올린다. 근거가 JIRA뿐이면 confidence `high`를 `medium`으로 낮춘다. `ANALYZED`인데 근거가 없거나, 상태·위험도·신뢰도 값이 틀리거나,
  fix-plan에 없는 `(좌표, from, to)`면 400. `NO_SOURCE`/`FETCH_FAILED`는 분석 필드를 모두 비운다(모델 추측이 남지 않게).
- **API:** `GET /api/ai/impacts/pending`, `POST /api/ai/impacts`. 결과는 `GET /api/fix-plans/{appId}`의 각 change에 `impact`로 붙는다(없으면 null).
- **화면:** 고정 메뉴 **조치안**(`program/fix-plan.html`, 로그인만 필요 — `FixPlanController`에 `@RequiresProgram`이 없다). 시스템을 고르면
  요약(전략·검토 상태·미해결/제외 CVE, 판단 근거·수정된 pom.xml은 모달)과 변경 그리드(점프·호환성 위험·신뢰도·breaking 수·분석 상태)를 보여주고,
  AI가 판단한 값에는 `(AI)`를 붙이고 "조치 전 원문 확인" 안내를 둔다. **호환성 위험(`UpgradeImpact.risk`)은 CVE 심각도가 아니라 그 버전으로 올릴 때
  앱이 깨질 위험**이다(HIGH: 코드·설정 수정 필수 / MEDIUM: 동작 변경 가능 / LOW: 근거상 breaking change 없음 — `impact.system.md`의 risk 기준).
  신뢰도는 모델이 스스로 매긴 값이라 측정된 정확도가 아니다.
  행을 클릭하면(상세 버튼 칸 없음 — 표가 넘쳐 밀려났다) breaking change(출처 링크)·조치·테스트 영역·근거 문서·메모를 연다. 분석 상태는 PATCH면
  "분석 제외", UNKNOWN이면 "확인 필요(버전)", impact가 없으면 "분석 대기", NO_SOURCE는 **"확인 필요(문서 없음)"**, FETCH_FAILED는 "수집 실패"다
  (패치를 "대기"로 보이면 영원히 기다리는 것처럼 읽히고, NO_SOURCE를 "근거 없음"이라 하면 "문제될 근거가 없다(안전)"로 읽힌다 — 실제로는 영향을 모른다).
  뱃지 색은 노랑=사람이 확인해야 함, 파랑=배치가 알아서 처리함. fix-plan이 없는 앱은 404를 오류가 아니라
  "아직 조치안이 없음"으로 보여준다. AI 문자열은 전부 textContent로 넣고 링크는 http(s)만 만든다.
- **우리 코드 대조(앱별, AI 없음):** AI가 breaking change마다 가리키는 이름(`symbols` — 클래스 전체 이름·영향받는 패키지·설정 키)을 내고,
  서버가 조회 시점에 앱의 소스 사용 목록과 대조한다(`CodeUsageMatcher`). **코드도 목록도 AI로 보내지 않는다.**
  - 목록: 스캔 때 clone을 지우기 전에 `SourceUsageExtractor`가 `.java`의 import 줄(정규식, static은 클래스까지)과 `application*.properties/yml`의
    **키 이름만**(값은 버림, YAML은 SafeConstructor) 뽑아 `ScanSnapshot.sourceUsageJson`에 둔다. target/build 등은 건너뛴다. 실패해도 스캔은 계속(null).
  - 판정: `USED` = 정확한 클래스(중첩 포함)·영향받는 패키지·설정 키(정확히 또는 이름이 바뀐 접두어, relaxed binding) 일치.
    `POSSIBLE` = 짧은 클래스 이름·와일드카드 import(p.*)에 대상 클래스로만 걸림(이름만 같은 다른 클래스일 수 있어 낮춘다).
    `NOT_FOUND` = import·설정 키에 없음 — **영향 없음이 아니다**(전체 이름 사용·리플렉션·XML·다른 라이브러리 경유는 못 잡는다).
    `UNKNOWN` = 이름이 없는 변경, symbols가 없는 예전 분석 결과, 소스 목록이 없는 스냅샷(다시 스캔하면 채워짐).
    전체는 하나라도 USED면 USED, 아니면 POSSIBLE, 판단 불가가 섞이면 UNKNOWN이다. 점 없는 이름·클래스처럼 보이는 이름은 설정 키와 대조하지 않는다.
  - 결과는 `GET /api/fix-plans/{appId}` 각 change의 `codeUsage`(impact 분석 완료이고 breaking이 있을 때만). 화면 "우리 코드" 칸은
    "사용 발견 1/3"처럼 건수를 함께 보여주고(그래서 breaking 건수 칸을 없앴다), 상세에는 항목별 결과와 걸린 import(파일 수)를 보여준다.

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

앱(`App`)에는 담당자 이름·이메일(`managerName`, `managerEmail`)이 있다. 로그인 계정(`User`)에는 이메일이 없고 담당자가
계정 없는 개발자일 수 있어 User를 참조하지 않는다. 이메일은 저장할 때 `AppService`가 느슨한 형식 검사만 한다(틀리면 400).

### 공통 자산

| 파일 | 역할 |
| --- | --- |
| `/css/common-ui.css` | `:root` 변수, `.app-shell`, `.btn`, `.panel-head`, `.page-toolbar`, 모달(`.modal-backdrop`+`.open` / `.modal` / `.modal-actions`), 모달 안의 라벨|값 상세 표(`.detail-list` — 취약점 관리 상세보기·조치안), 상태 뱃지(`.badge.<코드값 소문자>` — 처리여부·심각도·스캔 결과·점프 폭·영향 분석 상태) 등 페이지 뼈대. 화면 공통 버튼은 항상 우측 상단 — 제목과 한 줄이면 `.panel-head`, 조회조건 영역이 있으면 그 위에 `.page-toolbar` |
| `/css/grid.css` | `.grid` 공통 모양. 헤더 높이(45px)와 본문 행 높이(32px)를 모든 그리드에서 고정한다 — 화면 `<style>`에서 행 높이를 덮어쓰지 않는다. 헤더는 `position:sticky`라 세로 스크롤 때 고정된다. 행 안의 버튼(취약점 조회 스캔, 취약점 관리 상세보기)은 `.btn.grid-btn` |
| `/js/grid.js` | (`Grid.copyText`는 그리드 밖에서도 쓰도록 공개한 클립보드 복사 — https가 아니면 execCommand 폴백. 조치안 pom.xml 모달이 쓴다) 컬럼 정의(`COLUMNS`)로 헤더·행·입력 셀까지 만드는 공통 그리드 렌더러. `renderHeader`가 tbody의 첫 안내 행("조회 중입니다...", colspan 자동)도 넣으므로 템플릿의 `<tbody>`는 비워 둔다. 행 데이터는 `getRows`/`getRow`(원본 row + 입력 셀 현재 값, `_rowIndex`/`_isNew`/`_selected`)로 읽고 `onRowClick(tr, row)`도 같은 값을 받는다. select 컬럼에 `display(value, label, row)`를 주면 평소엔 그 결과(뱃지 등)를 보여주고 셀을 누를 때만 select로 바뀐다(취약점 관리 처리여부). 또 table을 `.grid-scroll`로 감싸고 숫자 `width`를 최소 폭으로도 적용해, 화면보다 넓으면 가로 스크롤이 생긴다. `.grid-scroll`의 세로 한도(`max-height`)는 grid.js가 "그 영역 시작 위치부터 화면 아래 끝까지"로 계산해 넣어(헤더·행을 그릴 때, 창 크기 변경 때), 행이 많으면 페이지가 아니라 그리드 본문만 스크롤된다(최소 200px). 화면이 스크롤 영역을 직접 둔 경우(`.grid-wrap`, 취약점 관리)는 감싸지 않는다. **모든 그리드 공통으로** 클릭한 셀에 테두리(`td.cell-current`)를 그리고, 데이터 셀 우클릭 시 공통 메뉴(셀 복사 / 행 복사(탭 구분) / 엑셀 다운로드)를 띄운다 — 값은 화면에 보이는 값(입력 셀은 현재 입력값, select는 옵션 이름)이고 id 없는 컬럼(행 선택·버튼 열)은 행 복사·엑셀에서 빠진다. 입력 셀(에디터) 위에서도 같은 메뉴가 뜨고, 우클릭으로는 입력칸에 커서가 들어가지 않는다(mousedown 기본 동작 차단). 클립보드는 http(비보안 컨텍스트)면 `execCommand` 폴백. 헤더(th)를 드래그앤드롭하면 컬럼 순서가 바뀐다 — 화면이 넘긴 컬럼 배열을 제자리에서 바꾸므로(`moveColumn`) 재조회해도 유지되고 새로고침하면 원래 순서다. **그래서 화면 코드가 컬럼을 순번(`cells[i]`, `COLUMNS[i]`)으로 가정하면 안 된다** — 행 데이터는 항상 `col.id`로 읽는다 |
| `/js/xlsx-writer.js` | 외부 라이브러리 없는 최소 .xlsx 작성기(무압축 zip + 시트 XML). `XlsxWriter.download(파일명, {sheetName, headers, widths, rows})`. 모든 셀을 문자열로 넣는다 — CSV면 엑셀이 버전 `1.10`을 숫자 1.1로 바꾼다. 헤더는 화면 그리드처럼 항상 가운데 정렬 + 배경 RGB(31,56,100)·흰 굵은 글꼴(`HEADER_FILL`). `loading-overlay.html`이 싣는다 |
| `/js/modal-drag.js` | 공통 모달(`.modal-backdrop` > `.modal`)을 첫 `h3`(제목줄)로 끌어 옮긴다. `transform`으로만 움직여 닫히면(`.open` 제거) 위치가 초기화되고, 제목줄이 화면 밖으로 못 나가게 막는다. 끌다가 백드롭 위에서 놓으면 생기는 click을 삼켜 "백드롭 클릭 = 닫기"가 오작동하지 않게 한다. `loading-overlay.html`이 싣는다 — **새 모달은 제목을 `h3`로 두기만 하면 된다** |
| `/js/com-cd.js` | 공통코드로 select 옵션 채우기(그룹당 1회 캐시) |
| `/js/tabs.js` | 홈 화면 탭 |
| `/js/hotkeys.js` | 공통 펑션키 F3 조회 / F4 신규 / F5 삭제 / F9 저장 / F12 초기화. 버튼에 `data-hotkey="F3"`만 붙이면 되고, 버튼 글자 뒤 `[F3]` 표기도 이 파일이 자동으로 붙인다. `loading-overlay.html`이 싣는다 |
| `/js/search-form.js` | 조회영역 공통 렌더러 `SearchForm.render(container, fields, {onSearch})` → `values()`/`reset()`/`field(id)`/`matches(row)`/`ready`. `matches(row)`는 전체 목록을 받아 조회조건을 화면에서 거르는 화면(프로그램·사용자·공통코드 관리, 취약점 조회)이 쓴다 — text 필드마다 `row[field.id]` 부분 일치(대소문자 무시). 화면은 `<section class="search-row" id="searchArea">`만 두고 label/input 마크업을 직접 쓰지 않는다 |
| `fragments/page-toolbar.html` | 화면 첫 줄 — 좌상단 프로그램명 + 우측 상단 공통 버튼. 값(`programNm`, `pageButtons`)은 `ViewController`가 넣는다. 버튼은 마크업에 쓰지 않는다(아래 "화면 공통 버튼" 참고) |
| `/js/page-buttons.js` | `PageButtons.bind({ btnSave: fn })` — 권한 때문에 안 그려진 버튼은 건너뛰고 핸들러를 건다. `loading-overlay.html`이 싣는다 |
| `fragments/loading-overlay.html` | 전역 스피너 + **CSRF 헤더를 붙이는 공통 fetch 래퍼** + `hotkeys.js`·`page-buttons.js`·`xlsx-writer.js`·`modal-drag.js` 로드 |

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
| `claude.api.key` | AI 판단 / fix-plan / 설명 요약 |
| `ai.internal.token` | 자바 ↔ 파이썬 배치 인증 (`CVE_MONITOR_AI_TOKEN`과 같은 값) |
| `ai.python.command` | 파이썬 실행 명령 (이 PC는 `py`) |
| `ai.assessor.script` | 배치 스크립트 경로 (`../ai/vuln_assessor.py`) |
| `ai.assessment.severities` | AI 판단 대상 등급 (기본 `HIGH,CRITICAL`) |
| `github.token` | 선택. 영향 분석이 GitHub Releases를 받을 때 쓰는 읽기 전용 토큰. 배치에 `GITHUB_TOKEN`으로 넘긴다. 없으면 토큰 없이 부른다 |
| `ai.auto-trigger.enabled` | 스캔 후 AI 배치 자동 실행 스위치의 **초기값**(기본 `true`, DB를 처음 만들 때만 쓰인다). 실제 스위치는 공통코드 `AI_CONFIG`/`AUTO_TRIGGER`의 사용여부로, 공통코드 관리 화면에서 바꾸면 재기동 없이 다음 스캔부터 적용된다(`ComCdService.isEnabled`). DB를 처음 만들 때만 이 값으로 심는다(파일 DB라 재기동해도 공통코드 값이 유지된다). 로컬은 `false`로 두면 과금 없이 스캔할 수 있다 |
| `scan.allowed-repo-hosts` | 앱 등록을 허용할 저장소 호스트 목록(쉼표 구분, 기본 `git.sejung.co.kr`). 다른 호스트를 쓰게 되면 여기서 늘린다 |

AI 배치 실행 로그는 `backend/ai-assessor.log`에 이어 쌓인다(gitignore 대상). 줄마다 `[YYYY-MM-DD HH:MM:SS][traceId]`가 붙는다(`_TimestampedStream`, traceback 포함). traceId는 실행마다 하나 — 서버가 띄우면 `AiAssessmentTriggerService`가 만들어 `CVE_MONITOR_TRACE_ID`로 넘기고 서버 로그의 "배치 실행 시작/종료" 줄에도 찍는다(사람이 직접 돌리면 파이썬이 만든다). 실행마다 `===== AI 배치 시작 =====` / `===== AI 배치 종료(exit=N) =====` 줄과 끝의 빈 줄이 남는다. 서버가 `PYTHONIOENCODING=utf-8`로 띄워 로그는 UTF-8이다(예전엔 윈도우 기본 cp949라 IDE에서 한글이 깨졌다).

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
- `ComCdServiceTest` — 설정 스위치 공통코드의 켜짐 판단(사용여부 Y/N, 코드 없으면 기본값)
- `VersionJumpClassifierTest` — fix-plan 버전 변경의 점프 폭(접미사·캘린더 버전·자리 부족·다운그레이드·해석 불가)
- `FixPlanServiceTest` — fix-plan 변경 목록 중 형식이 틀린 항목만 버리기
- `UpgradeImpactServiceTest` — 영향 분석 결과 정규화(출처 없는 항목 버리기, 메이저→HIGH, JIRA만이면 신뢰도 하향, 근거 없는 ANALYZED 거절, NO_SOURCE는 분석 필드 비우기, 대조용 이름 정리)
- `CodeUsageMatcherTest` — 우리 코드 대조(정확한 클래스·패키지·설정 키는 사용 발견, 짧은 이름·와일드카드는 가능성, 점 없는 이름은 설정 키와 비교 안 함, 메서드가 붙은 이름, 판단 불가 섞이면 전체 판단 불가, 소스 목록 없음)
- `SourceUsageExtractorTest` — import 추출(static·와일드카드·중복), properties/yml 키만 추출(값 버림, 깨진 파일 건너뜀), 빌드 폴더 제외·파일 수 집계
- `ScanHistoryServiceTest` — 스캔 이력의 신규 건수 계산(전후 OPEN 키 비교), 시작·성공·실패 기록, 오류 문구에 내부 메시지 미노출, 이력 저장 실패가 스캔을 막지 않음
- `CveSummaryServiceTest` — 설명 요약 대기 판단(CVE ID 단위, 해시 비교, 최신 설명 선택)과 저장 검증

파이썬은 `ai/test_release_notes.py`(unittest, 네트워크 없음) — 릴리스 노트 수집기의 버전 범위·절 자르기·HTML 본문 추출·scm 해석·총량 상한,
가짜 세션으로 본 수집 순서(공식 문서가 있으면 GitHub·Maven Central을 부르지 않음, 없으면 POM의 scm을 따라감).

즉 **컨트롤러·보안·화면에는 자동 테스트가 없다.** 그 영역의 변경을 분석할 때 "테스트가 통과했으니
안전하다"고 결론 내리지 않는다.

---

## 9. 프롬프트 자산

`ai/prompts/`에 시스템 프롬프트가 있고, 공통 규칙은 `ai/prompts/rules/*.md`로 쪼개져
`{{include: rules/xxx.md}}` 한 줄로 합쳐진다(`ai/prompt_rules.py`).

- `assess.system.md` — CVE 개별 판단
- `fix_plan.system.md` — pom.xml 수정안
- `summarize.system.md` — NVD 설명 한국어 요약(stage 3, Haiku). 규칙이 다른 프롬프트와 겹치지 않아 `rules/`를 include하지 않는다
- `impact.system.md` — 업그레이드 영향 분석(stage 4). 근거 문서만 쓰고 항목마다 출처 URL을 달게 한다. 역시 `rules/`를 include하지 않는다
- `ai/release_note_sources.json`(프롬프트가 아니라 수집 규칙) — groupId별 공식 문서 URL
- `rules/` — `false_positives.md`, `maven_strategy.md`, `version_matching.md`
