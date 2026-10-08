# llm-analysis.md — 분석용

**이 문서는 "지금 시스템이 어떻게 되어 있는가"(사실)만 적는다.**
코드를 읽고 파악·조사·설명·리뷰할 때 먼저 읽는다. 무엇을 어떻게 만들지(규범)는
[`llm-development.md`](llm-development.md)에 있다.

---

## 1. 무엇을 하는 시스템인가

등록된 Git 저장소의 보안취약점을 점검·관리하는 **보안취약점 모니터링 시스템**(프로젝트 이름 `security-monitoring`)이다. 두 기능으로 나뉜다.

- **라이브러리 취약점(CVE):** clone → 의존성 추출 → 취약점 DB 조회 → 판정 → pom.xml 수정안 생성까지를 한 줄로 잇는다(아래 흐름).
- **시큐어코딩 점검:** 같은 저장소의 소스를 행안부 SW 보안약점 규칙(Semgrep)으로 점검하고 연계 추적으로 판정한다. 그래도 못 정한 높은 등급만 AI가 코드를 보고 판별한다(3장 "시큐어코딩 점검", 4장 "코드 점검 AI 판별").

처음엔 CVE 모니터링(`cve-monitoring`, 패키지 `com.sjinc.cvemonitor`)으로 시작해 2026-10-06에 이름을 바꿨다
(패키지 `com.sjinc.securitymonitor`, `SecurityMonitorApplication`, 배치 환경변수 `SECURITY_MONITOR_*`).
H2 DB 파일(`data/cvemonitor.mv.db`)만 옛 이름이다 — 이름을 바꾸면 서버가 새 빈 DB를 만들어 기존 데이터를 못 찾으므로, 바꾸려면 서버를 멈춘 상태에서
파일(`.mv.db`·`.trace.db`)을 옮기고 `spring.datasource.url`을 같이 고친다.

```
[앱 등록]  →  [스캔]  →  [CVE 저장]  →  [자동/AI 판단]  →  [fix-plan 생성]  →  [화면 조회]
 app-mgmt     GitClone      NVD 보강         결정론 우선        pom.xml 수정안      Thymeleaf
              Maven tree    Vulnerability   → 애매할 때만 AI
              OSV 조회
```

| 모듈 | 역할 |
| --- | --- |
| `backend/` | Spring Boot 3.3.4 / Java 17 / Maven. 서버 + 화면(Thymeleaf) 전부 |
| `securecode/rules/` | 시큐어코딩 점검 규칙(Semgrep YAML) + 규칙별 테스트 예제. 라이브러리 취약점과 분리된 기능(아래 "시큐어코딩 점검")이 쓴다 |
| `ai/` | 파이썬 배치. 진입점은 `vuln_assessor.py`(서버 설정 `ai.assessor.script`)이고, 기능별로 파일이 나뉜다 — `cve_assessor.py`(라이브러리 취약점 stage 1~4),
`secure_code_reviewer.py`(시큐어코딩 판별 stage 5), `ai_common.py`(모델·백엔드 접속·응답 처리·토큰 집계·배치 로그 형식). 진입점이 둘을 차례로 돌리고
요약을 한 번에 찍는다. 한쪽이 예외로 멈춰도 다른 쪽은 돌고, 종료 코드는 실패(1)로 남는다. 한 기능만 돌리려면 그 모듈을 직접 실행한다. 스캔이 끝나면 할 일이 있을 때 서버가 띄우고(`AiAssessmentTriggerService`, 아래 4장), 사람이 직접 실행해도 된다. 어느 쪽이든 **배치가 드라이버다** — 배치가 `/api/ai/**`를 호출해 대기 중인 취약점·fix-plan·설명 요약·영향 분석·코드 점검 판별을 스스로 가져가고 결과를 되돌려준다. 자바는 띄우기만 하고 결과를 기다리지 않는다 |

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
com.sjinc.securitymonitor
├── config       # Spring 설정 (SecurityConfig, WebClientConfig, DataInitializer)
├── controller   # REST API (@RestController) — 화면용 컨트롤러는 여기가 아니라 mvc/
├── mvc          # 화면(뷰) 반환 컨트롤러 + 전역 모델(ControllerAdvice)
├── domain       # JPA 엔티티
├── dto/{ai,app,comcd,nvd,osv,permission,program,scan,securecode,user,vulnerability}
├── exception    # 기능이 정의한 예외(SecureCodeScanException)
├── repository   # JPA Repository
├── security     # @RequiresProgram + 이를 읽는 AuthorizationManager, ProgramAccessGuard, CsrfCookieFilter
└── service/{ai,app,comcd,git,maven,nvd,osv,permission,program,scan,securecode,user,vulnerability}
```

`service/securecode`만 하위 패키지가 있다(2026-10-08에 한 폴더 29개 클래스를 나눴다):

| 패키지 | 들어 있는 것 |
| --- | --- |
| `service.securecode` | 점검 흐름(`SecureCodeScanService`)·결과 저장·재점검 비교·코드 조각/지문·업로드 압축 해제·폐기 규칙 정리 |
| `service.securecode.semgrep` | `SemgrepRunner`·`SemgrepReportParser`·`RuleSetLoader` |
| `service.securecode.trace` | 연계 추적 엔진 — `JavaSourceIndex`·`MapperXmlIndex`·`ValueOriginTracer`·`ConstantFolder`·`MybatisDollarTracer`·`SinkTracer`·`DollarTraceMerger`·`UserScopeFindings` |
| `service.securecode.tracerule` | 추적 규칙 — `TraceRules`(설정)·`TraceRuleService`·`TraceRuleDrafter`·`FrameworkProfiler`·`TraceRuleChange`·`TraceRuleChangePlanner`·`TraceRulesFileEditor`·`TraceRuleDraftPreview` |
| `dto.securecode` | 판정 값 `TraceSafety`(enum)·`DollarVerdict`도 여기 — 화면 DTO(`SecureCodeFindingView`)와 AI 판별 서비스가 같이 써서, dto가 service를 import하지 않게 |

패키지가 나뉘어 `JavaSourceIndex`·`MapperXmlIndex`와 그 일부 메서드, `MybatisDollarTracer.readSources`/`trace`, `SinkTracer` 생성자·`trace`·`apply`가
public이다(다른 하위 패키지가 쓴다). `ValueOriginTracer`·`ConstantFolder`는 `trace` 안에서만 쓰여 package-private 그대로다.

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
   (`getPendingFixPlanTargets`), 설명 요약 대기(`CveSummaryService.getPendingSummaryTargets`), 영향 분석 대기(`UpgradeImpactService.getPendingTargets`)가 하나라도 있으면 `AiAssessmentTriggerService.triggerAsync(BatchKind.CVE)`로 파이썬
   배치의 **라이브러리 취약점 단계만** 백그라운드로 띄운다(`vuln_assessor.py cve`, fire-and-forget, CVE 배치가 이미 떠 있으면 건너뜀). "새 CVE가 저장됐는가"가 아니라
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

### 시큐어코딩 점검 (`SecureCodeScanService`) — 라이브러리 스캔과 별개

같은 앱 등록을 쓰지만 **라이브러리 스캔과 서로 호출하지 않는 별도 기능**이다. 공유하는 것은 앱(`App`)·clone(`GitCloneService`)·화면 공통 자산뿐.
판정은 결정론(Semgrep + 연계 추적)으로 끝내고, **AI는 결정론으로 못 정한 높은 등급만 점검 뒤에 판별한다**(4장 "코드 점검 AI 판별" — 점검 서비스는
코드 문맥을 만들고 배치를 띄우기만 한다. 2026-10-06 추가, 그 전에는 AI를 쓰지 않았다).

1. 동시 실행 잠금(`ReentrantLock.tryLock`) — 이미 돌고 있으면 409(`SecureCodeScanException.busy`). Semgrep이 동시에 돌면
   `~/.semgrep/settings.yml`을 같이 쓰다 PermissionError가 난다(규칙 테스트 중 실제로 났다).
2. `appId`로 등록된 앱만(임의 URL 없음) → `SecureCodeScan` RUNNING 기록. **소스를 얻는 방법만 앱의 소스 출처에 따라 다르고 3번부터는 같다**(`analyze`):
   Git 앱은 `scan` → clone, 소스 업로드 앱은 `scanUpload` → zip 압축 해제(아래 "소스 업로드 점검")
3. `RuleSetLoader` — 규칙 폴더(`securecode.rules-dir`, 기본 `../securecode/rules`)의 `*.yml` 규칙 id 목록과 규칙셋 버전(내용 해시 12자리).
   규칙이 0개면 실패시킨다(0건 성공 → 기존 탐지 전부 해결 처리를 막기 위함)
4. clone → `SemgrepRunner`: clone 루트에 우리 `.semgrepignore`를 **지우고 새로 쓴 뒤**(저장소 쪽 파일·심볼릭 링크를 따르지 않게, `src/test/`·빌드 폴더 제외)
   `semgrep scan --config <규칙폴더> --json --output <임시파일> --metrics=off --disable-version-check --timeout 30 --no-git-ignore .`를
   clone 폴더에서 실행. 환경변수 `PYTHONUTF8=1`이 없으면 한글 경로에서 실행 자체가 실패한다. 출력·로그는 파일로 받고(파이프 막힘 방지), 전체 제한시간
   (`securecode.timeout-seconds`, 기본 600)을 넘기면 강제 종료. exit 0이 정상(탐지가 있어도 0)
5. `SemgrepReportParser` — 규칙 id는 `check_id`의 마지막 점 뒤(Semgrep이 설정 경로를 앞에 붙인다), 경로는 `/`로, 심각도는 ERROR/WARNING/INFO →
   공통코드 SEVERITY의 HIGH/MEDIUM/LOW. `errors` 중 경로가 있는 것은 **분석 실패 파일**로 센다
6. `SecureCodeSnippetBuilder` — 무료판 Semgrep은 `extra.lines`·`fingerprint`에 `"requires login"`을 넣어서, 서버가 clone 파일을 직접 읽어
   조각과 **지문**을 만든다. 조각은 걸린 줄을 감싼 메서드(매퍼 XML이면 감싼 `<select>`·`<insert>`… 구문, 못 찾으면 앞뒤 5줄)이고 길면
   걸린 줄 가운데로 80줄(`SNIPPET_MAX_LINES`) — 2026-10-07 전엔 앞뒤 5줄이라 같은 메서드 안의 요청값 받는 줄도 잘렸다. 지문 = SHA-256(규칙 id + 파일 경로 + 걸린 줄의 공백 정리 텍스트 + 같은 키의 파일 내 순번). 줄 번호는 넣지 않는다
   (위에 한 줄 추가로 전부 "해결+신규"가 되지 않게). 규칙 id에 `hardcoded-secret`이 들어가면 조각·지문 모두 문자열 리터럴·설정 값을 `****`로 가린 뒤 쓴다.
   UTF-8로 깨지면 MS949로 다시 읽는다. 저장소 밖(실제 경로 기준, 심볼릭 링크 포함)을 가리키면 읽지 않는다.
   연계 추적 뒤에는 근거 걸음마다("파일명:줄 …") 그 줄 앞뒤 3줄을 `traceCode`(TraceStepCode 목록 JSON, 근거와 같은 순서, 없는 걸음은 null)로 붙인다
   (`SecureCodeScanService.attachTraceCode`) — 근거는 다른 파일·메서드를 가리키는데 clone은 점검이 끝나면 지워 나중에 읽을 수 없다. 근거는 파일 이름만 적으므로
   경로로 되돌릴 때 탐지 파일 자신 → 후보가 하나 → 탐지 파일과 경로 앞부분이 가장 길게 겹치는 것 순으로 고르고, 못 고르면 비운다(엉뚱한 파일을 보여주지 않게)
6-1. **연계 추적** — 출처를 따라갈 수 있는 탐지가 있을 때만(`SecureCodeScanService.traceFindings`). clone의 Java 소스를 한 번만 구문 분석해
   (`JavaSourceIndex` — JavaParser, 타입 해석기 없이 소스만) 아래 두 추적이 같은 색인을 쓴다. 값의 출처를 따라가는 엔진은 `ValueOriginTracer`(순수)다 —
   지역 변수는 모든 대입(단 상수 조건으로 실행되지 않는 갈래와, 쓰기 전에 같은 블록에서 무조건 다시 대입돼 덮인 값은 뺀다 — `ConstantFolder`), 파라미터는 모든 호출자(호출 문맥 Frame), 맵은 실행 직전까지 모든 경로의 `put`, 우리 메서드는 반환문(값이든 맵이든 — 맵을 만들어 돌려주는 유틸 메서드의 키도 그 안의 `put`까지 따라간다. 2026-10-07 전에는 맵 쪽이 빠져 `FrameFileUtil.excelToTxt(...)`가 돌려준 맵이 "맵 출처를 모름"이었다), 컨트롤러 요청 매핑 파라미터는
   클라이언트 값, 세션 덮어쓰기·로그인 정보는 `trace-rules.yml`. JDK 값 객체(날짜·난수·UUID·숫자 — `PURE_VALUE_TYPES`)·클래스 정적 메서드·정적 상수는
   재료(받는 쪽·인자)의 출처를 따르고, 클라이언트가 보낸 객체(업로드 파일 등)의 메서드 결과는 클라이언트 값이다. RestTemplate·SqlSession처럼 외부에서
   값을 가져오는 객체의 결과는 판정 불가로 둔다. 메서드 연결(`JavaSourceIndex.resolve`)은 타입 해석기 없이 이름으로 하므로, 같은 이름의 클래스가 여럿이면
   호출 지점에서 보이는 것만 고른다(같은 파일 → 단일 import → 같은 패키지, 못 고르면 전부). `ConstantFolder`(순수)는 리터럴·한 번만 정해지는 지역 변수·
   static final 필드와 그 사이의 사칙연산·비교·`String` 메서드(`charAt`·`equals` 등)를 계산해 if·삼항·switch(fall-through 포함)·`while (false)`의
   실행되지 않는 갈래를 가리고, 빈 지역 리스트에 같은 블록에서 차례로 add·remove·set만 한 뒤 상수 위치로 꺼내는 `get(i)`의 원소를 계산한다.
   모르면 계산하지 않는다(그 갈래는 실행될 수 있다고 보고 판정은 가장 나쁜 쪽으로 남는다). 판정은 `TraceSafety`(공용 enum), 등급은 `TraceSafety.severity()` — 클라이언트 값·우회 가능 HIGH,
   판정 불가 MEDIUM, 안전 판정 LOW. 판정·근거는 `SecureCodeFinding.traceSafety`·`traceEvidence`에 저장하고, 지문은 그대로라 재점검 비교·처리여부에 영향이 없다.
   - **위험 호출 지점**(`SinkTracer`): SSRF 변수 주소(`kisa-ssrf-dynamic-url`)·명령 실행(`kisa-os-command-exec`, 같은 호출을 taint로 보는 `kisa-os-command-injection-request`도 같은 기준 —
     taint는 상수 조건을 계산하지 못해 실행되지 않는 요청값 갈래로도 HIGH가 되고 추적이 없으면 AI 대기로 갔다)·다운로드 경로(`kisa-path-traversal-download`)·
     업로드 저장(`kisa-file-upload-save`)·문자열 연결 SQL(`kisa-sql-injection-java-concat`) 탐지 줄에서 규칙이 보는 호출을 구문 트리로 다시 찾아(`JavaSourceIndex.nodesAt`)
     그 인자(주소·명령·경로·SQL)의 출처를 판정한다. 무료판 Semgrep taint는 한 메서드 안만 봐서, 컨트롤러가 받은 값을 서비스에서 쓰는 사내 구조에서는
     Spring 출처를 넣어도 이어지지 않던 것을 호출자를 거슬러 컨트롤러까지 따라가 확정한다. SSRF는 고정 호스트로 시작하는 주소(지역 변수에 만든 것도)를
     안전으로 본다(규칙의 sanitizer와 같은 기준). 호출을 못 찾으면 판정을 붙이지 않는다(Semgrep 등급 그대로).
   - **실측(2026-10-06):** CRM_BACK 6건 — 업로드 저장 4건 중 원래 파일명의 확장자를 저장 경로에 쓰는 2곳(`Crc020Service:898`·`Crd010Service:72`, `.jsp` 업로드
     가능)은 HIGH, 설정값 + 날짜 + 난수로 이름을 만드는 2곳은 LOW. SSRF 변수 주소 2건(`callUrl` 대입 3곳 모두 서버 값, `batchUrl` `@Value`)은 LOW.
     ext-api 2건 — 상수 주소를 넘겨받은 `new URL(url)` LOW, 외부 HTML의 `img.attr("src")`는 판정 불가.
     처음엔 `.append()` 체인 깊이(MAX_DEPTH 14 → 40), JDK 날짜·난수 객체, `File.separator` 같은 클래스 상수를 몰라 안전한 2곳이 판정 불가였다.
   - **OWASP Benchmark 1.2 SQL 인젝션(2026-10-07, sqli 504건 = 실제 취약 272 + 오탐 유도 232):** 규칙 수정 전 탐지 0건이었다 —
     `kisa-sql-injection-java-concat`이 실행 인자 바깥 모양 `"..." + $E`만 봤는데, `+`는 왼쪽 결합이라 `"... '" + bar + "'"`의 바깥은
     `("... '" + bar) + "'"`(식 + 리터럴)이다. 깊은 식(`<... "..." + $E ...>`)으로 바꾸고 `execute(sql)`처럼 변수에 먼저 만든 SQL도 잡게 해 504/504.
     추적은 패키지까지 쓴 정적 호출(`java.net.URLDecoder.decode(...)` — `isClassScope`), 컬렉션 넣기/꺼내기(`list.add` → `list.get`, 이터레이터·
     `Enumeration` — `COLLECTION_*`), 요청 맵·이름 목록(`getParameterMap`·`getParameterNames`·`getHeaderNames`)을 몰라 미탐이 났다. 고친 뒤
     HIGH 보고 기준 탐지율 100%(272/272, 전: 53.7%), 오탐률 68.5%(159/232). 남은 오탐은 Benchmark의 상수 조건 함정
     (`(7*42) - num > 200 ? ... : param`, `switch("ABC".charAt(1))`, 리스트 `remove(0)` 뒤 위치 선택, 덮어쓴 대입)이었다 — `ConstantFolder`를 넣어
     22.8%(53/232). 마지막 53건은 파일마다 있는 내부 클래스 `private class Test`의 `doSomething`이 이름만으로 다른 파일들의 같은 메서드에 이어진 것이라
     메서드 연결을 보이는 클래스로 좁혀 **탐지율 100%, 오탐률 0%(0/232), 판정 불가 2건(오탐 유도)**. 측정 도구: `BenchmarkEvalTest`(`-Dbench.dir`이 있을 때만 돈다).
   - **같은 줄·같은 CWE 합치기**(`DuplicateCweMerger`, 연계 추적 뒤·AI 문맥 전): 한 약점을 두 방식으로 보는 규칙 쌍(명령 실행 taint + 실행 호출,
     SSRF `kisa-ssrf-request` + `kisa-ssrf-dynamic-url`)은 한 메서드에서 끝나는 코드에서 같은 줄 두 건이 되고 추적을 받는 쪽만 판정이 붙어 HIGH·LOW가
     엇갈렸다. 같은 파일·줄·CWE에 다른 규칙이 여럿이면 한 건만 남긴다 — 남길 규칙은 점검마다 같아야 해서(지문에 규칙 id) 판정 유무가 아니라 규칙만 보고
     고른다(연계 추적을 받는 규칙 → 규칙 id 순). 남은 건에 추적 판정이 없으면 등급은 묶음에서 가장 높은 것(그러면 AI 판별 대상), 설명 끝에 함께 걸린 규칙을
     적는다. 같은 규칙이 한 줄에 여럿(`${a}`·`${b}`)이거나 CWE가 없으면 합치지 않는다. 합쳐 빠진 기존 탐지는 `SecureCodeReconciler`가 RESOLVED +
     비고 "같은 줄·같은 CWE의 … 탐지와 한 건으로 합침"(`retireRule`, 사람이 정한 상태는 유지, "해결" 건수에는 넣지 않음). Benchmark 3,568건 중 460묶음
     (SSRF 312, 명령 실행 148).
   - Set.of는 JVM마다 순회 순서가 달라, 구문 실행 메서드를 그대로 돌면 같은 코드인데 근거로 고르는 공통 실행 경로가 실행마다 바뀌었다 — 정렬해서 돈다.
6-1-a. **MyBatis `${}`** — `kisa-sql-injection-mybatis-dollar`. `MybatisDollarTracer`(순수)가 매퍼 XML(`MapperXmlIndex`)과 Java 소스를 이어 `${key}`마다
   값의 출처를 판정하고, `DollarTraceMerger`가 (파일, 줄, 줄 안 순서)로 탐지에 붙인다.
   - 따라가는 길: `${key}` → 구문 실행(`sqlSession.selectList("ns.id", map)`, 구문 id를 파라미터로 받는 감싼 메서드면 그 호출자까지) → 실행 직전까지
     `map.put("key", 값)`이 **모든 경로에서** 일어나는가(if 한쪽·반복·catch·람다 안이면 조건부 — `@RequestBody Map`에는 클라이언트 키가 이미 있어서
     조건이 거짓이면 원래 값이 남는다) → 값이 상수·로그인 정보·모든 반환이 상수인 메서드인가, 요청 값인가. 맵이 파라미터면 호출자로, 컨트롤러 요청 매핑까지 가면 클라이언트 값.
   - **공통 실행 경로:** 클라이언트가 구문 id까지 정하는 실행(`selectList(param.getStatement(), paramData)`)을 찾아 모든 구문의 추가 호출처로 함께 판정한다.
     서비스에서 세팅한 값도 그 경로로 직접 부르면 우회되기 때문이다. List를 넘기는 실행은 MyBatis가 `list`로 감싸 `${key}`에 닿지 않아 판정에서 뺀다.
   - 판정: 클라이언트 값·공통 경로로 우회 가능 → HIGH, 판정 불가 → MEDIUM, 세션 값으로 덮어씀·서버가 세팅·XML에서 결정(bind 상수, 상수 비교 if/when 안) → LOW.
     안전 판정이 직접 경로에서 나왔고 공통 실행 경로도 있으면, 그 경로로 와도 안전한 이유("공통 실행 경로로 이 구문을 직접 불러도 세션 값으로 덮어씀: …")를
     근거에 한 줄 더 남긴다 — 직접 경로만 보이면 "공통 경로는 확인했나"를 알 수 없었다. 근거의 **마지막 줄은 항상 "매퍼파일:줄 식 (구문)"**이다(화면이 대상 식을 여기서 꺼낸다).
     안전해도 자동 오탐 처리는 하지 않는다. 재점검마다 최신 판정으로 바꾼다.
   - **시스템별 프레임워크 규칙은 `securecode/trace-rules.yml`(`TraceRules`)에만 둔다** — 세션 값을 요청 맵에 덮어쓰는 장치(어노테이션·덮어쓰는 위치·
     첫 파라미터 조건·키), 로그인 정보로 볼 메서드 접두어·타입 이름. 판정 로직에는 특정 시스템 이름이 없다. 규칙은 대상 코드에 그 어노테이션이 있을 때만
     적용돼 여러 시스템 항목을 같이 둔다. 지금은 sjinc 프레임워크 `@AddUserInfo` 하나(첫 파라미터가 HttpServletRequest일 때 `paramData`의 login* 키).
     파일이 없으면 빈 규칙(덮어쓰기를 모르면 클라이언트 값 — 위험한 쪽). 규칙 폴더(`rules/`) 밖에 두는 이유는 그 안의 *.yml을 Semgrep이 규칙으로 읽어서다.
     **공통 + 시스템별**(2026-10-08): `sessionOverwrites`는 공통뿐이고(어노테이션이 있어야 적용돼 섞여도 간섭하지 않는다), `loginMethodPrefixes`·`loginTypeNames`·
     `userScopeKeys`는 공통 목록과 `systems.<시스템명>`(앱 관리의 시스템명) 목록이 있다. 점검은 `TraceRules.forSystem(시스템명)` — 공통에 그 시스템 항목을 더한
     규칙으로 한다(`TraceRuleService.Review.effective`). `compCd`·`getLogin`처럼 흔한 이름은 시스템마다 뜻이 달라(어떤 시스템에선 관리자가 고르는 조회조건),
     공통에 두면 다른 시스템의 정상 화면이 "부적절한 인가"로 쏟아지고, 공통 키가 하나라도 쓰이면 "키를 찾지 못함" 알림이 안 떠 그 시스템에 필요한 키가 빠진 걸
     모른다. 공통에는 여러 시스템이 같이 쓰는 사내 프레임워크(`@AddUserInfo`의 login* 키)만 둔다. 처음 CRM 점검으로 반영한 키 5개는 `systems."CRM_BACK"`으로 옮겼다.
     같은 파일 끝의 `frameworks`(시스템별 프레임워크 구조)는 **판정에 쓰지 않는 기록**이다(아래 "추적 규칙 확인"). 파일은 사람과 서버가 같이 고친다.
   - 추적은 부가 판정이라 실패해도 점검을 실패시키지 않는다. 대신 Semgrep 등급을 그대로 두고 `SecureCodeScanResult.traceNote`로 화면 알림에 올린다
     (추적 실패, 줄 안 개수가 달라 못 맞춘 건수, Java 구문 분석 실패 파일 수).
6-1-c. **iBatis 2(옛 시스템, 2026-10-07)** — sqlMap의 치환 `$값$`은 Semgrep 규칙 `kisa-sql-injection-ibatis-dollar`(MyBatis `${}` 규칙과 같은 파일 범위·
   주석 제외, `$` 뒤가 이름으로 시작해야 걸린다)가 잡고, 값 출처는 **같은 엔진**이 판정한다(`DollarTraceMerger.RULE_IDS`에 두 규칙). 매퍼 색인(`MapperXmlIndex`)은
   루트가 `<sqlMap>`이면 iBatis로 읽는다 — `$이름$`·`#이름#`(`#이름:VARCHAR#`·`#이름,jdbcType=…#`, 속성 경로 `a.b`·반복 `list[]`), 구문 태그에 `statement`·`procedure`,
   namespace가 없으면 id가 곧 전체 id, 동적 태그 `prepend`(WHERE·AND·OR → 조건 자리, SET → 값 자리), `<isEqual property compareValue>` 안이면 "XML에서 결정".
   실행 호출은 `queryForList`·`queryForObject`·`queryForMap`·`queryForPaginatedList`·`queryWithRowHandler`(+insert·update·delete)를 `SqlMapClient`·
   `SqlMapClientTemplate`(`getSqlMapClientTemplate()`)에서 인식한다. 근거·메시지·화면의 대상 식은 파일에 적힌 모양 그대로다(`Dollar.display` — `$sortCol$`).
   사용자 범위 판정도 같은 기준으로 `#값#`을 본다. Spring 어노테이션이 없는 진입점(Struts Action·서블릿)은 아직 요청 매핑으로 인식하지 못한다 —
   `request.getParameter`로 직접 꺼낸 값은 클라이언트 값으로 따라가지만, 프레임워크가 요청을 통째로 맵에 옮겨 넘기면 "판정 불가"가 된다.
6-1-b. **사용자 범위(인가)** — `kisa-authz-client-user-scope`(행안부 "부적절한 인가", CWE-639). **Semgrep 규칙이 아니라 연계 추적 판정이 탐지를 만든다**
   (`UserScopeFindings`). `trace-rules.yml`의 `userScopeKeys`(회사·브랜드·사용자로 데이터를 가르는 SQL 파라미터 키)가 매퍼 SQL의 **조건 자리**(WHERE·ON·HAVING)에
   `#{key}`로 쓰인 곳마다. 값 자리(INSERT VALUES·UPDATE SET·SELECT 목록)는 등록자·수정자 기록이라 뺀다 — CRM은 거의 모든 INSERT가 `#{loginEmpNo}`를
   등록자로 넣어 구분하지 않으면 인가 탐지가 쏟아졌다(`fileMapper.xml`의 `insert_txtFile`). 자리는 `MapperXmlIndex.clauseIsCondition`이 가른다: `<where>`·
   `<trim prefix="WHERE">` 안이면 조건, `<set>`·`<trim prefix="SET">` 안이면 값, 아니면 그 앞까지의 SQL(주석 제외)의 마지막 키워드(WHERE·ON·HAVING → 조건,
   SET·VALUES·UPDATE → 값 — `ON DUPLICATE KEY UPDATE`·MERGE도 맞게), 키워드가 없으면 insert는 값·나머지(조각 포함)는 조건(모르면 놓치지 않는 쪽).
   그런 곳마다
   `${}`와 같은 엔진(`MybatisDollarTracer` — 매퍼 색인이 `#{}`도 모은다, `MapperXmlIndex.Statement.hashes`)으로 실행 시점의 값 출처를 판정하고,
   **위험한 판정만** 탐지로 낸다: 클라이언트 값·공통 경로로 우회 가능 HIGH, 판정 불가 MEDIUM. 세션 덮어쓰기·서버 세팅·XML 결정은 내지 않는다(판정에서 만든
   탐지라 안전한 것까지 내면 거의 모든 SQL이 목록에 오른다). 위치는 조건이 쓰인 매퍼 SQL 줄, 근거는 컨트롤러 → 서비스 → 매퍼 경로. 코드 조각·지문은
   Semgrep 탐지와 같은 방법(`SecureCodeSnippetBuilder`)이라 재점검 비교·처리여부가 똑같이 동작한다. `${key}`로 쓰인 사용자 범위 키는 SQL 삽입 판정이 이미 같은
   방법으로 보므로 내지 않는다. (구문, 키) 판정은 메모해 재사용한다 — 사용자 범위 키는 거의 모든 구문에 여러 번 쓰인다.
   - **시스템이 다른 것은 키 이름(설정 — 공통 + `systems.<시스템명>`)뿐이다.** 키가 설정에 없으면 판정하지 않고 알림("userScopeKeys가 없어 판정하지 않음"), 키가 있는데 이 저장소 매퍼에
     하나도 안 쓰이면 "이 시스템의 키를 추가하세요" 알림 — "문제 없음"과 구분되게. 새 시스템은 그 시스템의 범위 키와(세션 값을 넣는 장치가 있으면) `sessionOverwrites`를 추가한다.
   - 이번 점검에서 판정을 끝까지 했을 때만 이 규칙 id를 활성 규칙에 넣는다(규칙셋에 없는 규칙이라) — 판정이 실패했거나 설정이 없어 안 했는데 넣으면 기존 탐지가 전부 "해결"이 된다.
   - **예전 규칙 `kisa-authz-missing-user-scope`(2026-10-07 폐기)**: "CRM의 `@AddUserInfo`·`FrameEtcUtil.addUserInfo`·세션 조회가 없는 컨트롤러 매핑 메서드"를
     후보로 냈다. `@AddUserInfo`는 로그인 정보를 넣어 주는 편의 장치일 뿐 강제가 아니고, 다른 시스템엔 없어 컨트롤러 거의 전부가 오탐이 되며, 사용자 범위 조건을
     쓰지 않는 메서드도 걸렸다. 남은 OPEN 탐지는 `SecureCodeRuleRetirement`가 기동 때 조치완료(비고 "규칙 폐기…")로 정리한다 — 재점검은 규칙셋에 없는 규칙의
     탐지를 해결 처리하지 않아 그대로 두면 영원히 OPEN이다. 규칙을 또 폐기하면 그 클래스의 `RETIRED_RULES`에 (id → 이유)를 추가한다.
6-2. **AI 판별 문맥** — `SecureCodeScanService.attachAiContext`. 연계 추적이 등급을 다시 매긴 뒤, AI 판별 대상(`SecureCodeAiReviewService.isTarget`)에만
   `SecureCodeSnippetBuilder.withAiContext`로 걸린 줄을 감싼 가장 안쪽 메서드·생성자(JavaParser, 파일 하나만)를 `aiContext`로 붙인다. 메서드가
   `AI_CONTEXT_MAX_LINES`(80줄)보다 길면 걸린 줄이 가운데 오게 자르고(메서드 끝에 닿으면 앞으로 당김), 자바가 아니거나 구문 분석 실패·메서드 밖이면
   걸린 줄 앞뒤 15줄. 비밀값 규칙은 조각과 같은 기준으로 가린다. clone이 지워지기 전에만 만들 수 있어 점검 때 저장한다. 실패해도 점검은 계속(화면용 조각을 보낸다)
7. `SecureCodeReconciler`(순수) → `SecureCodeFindingService.applyScan`(트랜잭션) — 새 지문은 OPEN, 있던 지문은 위치·조각 갱신(스캔이 해결한 건은 다시 OPEN),
   이번에 안 걸린 OPEN은 RESOLVED. **단 분석 실패 파일의 탐지와, 이번 규칙셋에 없는 규칙의 탐지는 해결 처리하지 않는다**
8. 이력 SUCCESS(파일·탐지·신규·해결·분석 실패 수, 엔진·규칙셋 버전) / 실패면 FAILED. 성공하면 `triggerAiReviewIfNeeded` — 자동 실행 스위치(`AI_CONFIG`/`AUTO_TRIGGER`)가
   켜져 있고 판별 대기(전체 앱)가 있으면 **시큐어코딩 단계만** 띄운다(`triggerAsync(BatchKind.SECURE_CODE)` → `vuln_assessor.py securecode`, 로그 `ai-securecode.log`).
   예전엔 배치 하나로 전체를 돌려 코드 점검 뒤 로그에도 할 일 없는 CVE 단계(CVE 판단 0건, fix-plan …)가 찍혔다. 두 종류는 따로 떠서 동시에 돌 수 있고 "이미 떠 있으면 건너뜀"도 종류별이다. 화면 오류 문구는 `IllegalArgumentException`·`SecureCodeScanException`만
   메시지를 그대로, 나머지는 종류만(내부 경로 노출 방지). clone은 finally에서 지운다

- **설치·기동 확인:** Semgrep 버전은 `securecode/requirements.txt`(`semgrep==1.178.0`)로 고정한다. `SemgrepRunner.checkOnStartup`(ApplicationReadyEvent, 별도 데몬 스레드)이
  `semgrep --version`을 실행해 없으면·고정 버전과 다르면 WARN 로그에 설치 명령을 남긴다. 기동은 막지 않는다(코드 점검은 부가 기능).
  고정 버전 파일은 `securecode.rules-dir`의 상위 폴더에서 읽는다. 배포 형태(개인 로컬 실행 / 공용 서버)는 아직 정하지 않았고 지금은 개인 로컬 기준이다.
- **엔티티:** `SecureCodeFinding`(`secure_code_findings`, 유니크 `(app_id, fingerprint)`), `SecureCodeScan`(`secure_code_scans`), `TraceRuleProposal`
  (`trace_rule_proposals` — 추적 규칙 변경 한 건과 처리 결과, 아래 "추적 규칙 확인"). 모두 앱을 FK로 잡지 않고 appId 값만 둔다 — 지워진 앱의 탐지는 조회에서 빠진다.
- **처리여부:** 공통코드 `SC_STATUS` = OPEN(미조치)/RESOLVED(조치완료)/FALSE_POSITIVE(오탐)/ACCEPTED(위험수용). 사람이 OPEN 외로 바꾸면 `statusManual=true`가 되어
  같은 지문이 다시 걸려도·안 걸려도 스캔이 바꾸지 않는다. OPEN으로 되돌리면 다시 스캔을 따른다. 코드가 바뀌면 지문이 바뀌어 새 건이 된다(판단도 다시).
- **심각도:** HIGH/MEDIUM/LOW뿐이다(Semgrep ERROR/WARNING/INFO, 연계 추적 판정 — CRITICAL은 라이브러리 CVE의 CVSS에만 있다). 그래서 코드 점검 결과
  조회조건은 라이브러리용 `SEVERITY`가 아니라 공통코드 `SC_SEVERITY`(HIGH/MEDIUM/LOW)를 쓴다 — 같은 그룹이면 걸리는 행이 없는 CRITICAL이 보였다.
  값이 같은 문자열이라 뱃지·정렬(`SeverityOrder`)은 그대로다. AI 판별 대상 등급 `ai.securecode.severities`도 기본 HIGH다.
  `SC_STATUS`·`SC_SEVERITY`는 `DataInitializer`가 **그룹이 없을 때만** 매 기동 심는다(사용자 0명일 때만 심는 다른 초기 데이터와 다르다 — 기존 DB에도 들어가야 해서).
- **소스 업로드 점검**(2026-10-07): Git으로 접근할 수 없는 앱(옛날 시스템 등)은 앱 관리에서 소스 출처를 "소스 업로드"(`App.SOURCE_UPLOAD`, 공통코드
  `APP_SOURCE`)로 두고 코드 점검 화면에서 소스를 올린다(`POST /api/secure-code/scan-upload` multipart `appId`·`file`). 행의 버튼이 둘이다 —
  **zip**(zip 파일 선택)과 **폴더**(브라우저 폴더 선택 `webkitdirectory`). 폴더는 화면이 점검 대상 파일만 골라(서버 `SOURCE_EXTENSIONS`와 같은 확장자,
  `node_modules`·`target`·`build`·`.git` 등 아래는 뺌) 공통 `ZipWriter`로 무압축 zip을 만들어 **같은 API**로 보낸다 — 서버의 경로 조작·크기·빈 zip 검사를
  그대로 받고, 수천 개 파일을 멀티파트로 따로 보낼 때의 Tomcat 파트 수 상한도 피한다. 이름은 `폴더명(폴더).zip`이라 이력에서 구분된다.
  ZIP64를 쓰지 않아 파일 65,535개·4GB를 넘으면 화면이 거부한다(그땐 zip으로 올린다).
  - 업로드 앱은 저장소 URL·브랜치가 없다(`AppService`가 지움 — 옛 URL로 clone되지 않게). 기존 DB의 `apps`·`secure_code_scans` `repo_url`·`branch` NOT NULL은
    `SchemaMigration`이 기동 때 푼다(ddl-auto=update는 제약을 풀지 않는다). **라이브러리 CVE 스캔은 못 한다** — 업로드된 pom.xml로 Maven을 돌리면 플러그인·저장소가
    서버에서 실행된다(스캔을 등록된 저장소로만 하는 것과 같은 이유). 취약점 조회 화면의 스캔 버튼이 비활성이고 `ScanOrchestrationService`도 거부한다
    (빈 저장소 값으로 찾으면 Spring Data가 IS NULL 조회를 해 업로드 앱이 잡히는 것도 먼저 막는다).
  - **업로드 앱만 zip으로, Git 앱은 저장소로만** 점검한다 — 섞으면 경로 기준이 달라져 탐지가 "해결+신규"로 뒤섞인다.
  - **권한:** 업로드 점검은 `@RequiresProgram("app-mng")` — 점검 버튼(로그인만)보다 높다. 올린 소스가 그 앱의 점검 결과를 대신하므로 엉뚱한 소스를 올리면
    기존 탐지가 "해결"로 바뀐다. 같은 이유로 **점검할 소스 파일(.java·.jsp·.xml 등)이 하나도 없는 zip은 거부**한다. 화면은 올리기 전에 "안 걸린 기존 탐지는 해결 처리됨"을 확인받는다.
  - **압축 해제(`SourceArchiveExtractor`, 순수):** 경로 조작(`../`·절대 경로·드라이브 문자 — 최상위 폴더를 벗기기 전 원래 이름으로 검사)이 하나라도 있으면 아무것도
    풀기 전에 전체 거부, 압축 폭탄은 실제로 쓴 바이트 합(`securecode.upload.max-extracted-bytes`, 기본 2GB)과 파일 수(`securecode.upload.max-entries`, 기본 20만)로 막는다.
    링크는 만들지 않는다(ZipFile은 일반 파일로 쓴다). 한글 파일명은 UTF-8로 읽다 깨지면 MS949. `__MACOSX/`·`._파일`은 건너뛴다.
    항목이 전부 한 최상위 폴더 아래면 그 폴더를 벗긴다 — 지문이 저장소 기준 경로라 "myapp/src/…"·"src/…"가 섞이면 재점검 비교가 깨진다. 실행은 하지 않는다(읽기만).
  - 업로드 크기 상한 `securecode.upload.max-bytes`(기본 500MB, `SecureCodeUploadConfig` — Spring 기본 1MB로는 소스 zip이 전부 거부된다). 넘으면 413과 안내 문구
    (`UploadSizeExceptionAdvice` — 컨트롤러를 고르기 전 멀티파트 해석 단계의 예외라 컨트롤러·REST 한정 advice로는 안 잡힌다). 크게 넘으면 서버가 연결을 끊을 수 있어 화면은
    fetch 실패도 "파일이 너무 클 수 있음"으로 안내한다.
  - 이력(`SecureCodeScan`)은 브랜치 대신 올린 zip 이름(`uploadFileName`)과 내용 SHA-256(`uploadSha256`)을 남긴다. 올린 zip과 푼 폴더는 점검이 끝나면 지운다.
- **API**(`SecureCodeController`, `/api/secure-code`): `POST /scan {appId}`(Git 앱), `POST /scan-upload`(multipart, 소스 업로드 앱, app-mng 권한), `GET /scans?appId=`(최신 500건), `GET /findings?appId=&status=`(기본 OPEN, 빈 값=전체 — 코드는 넣지 않는다), `GET /findings/{id}/code`(상세보기용 조각·연계 추적 근거 코드 `SecureCodeFindingCode`
  — 조각이 메서드 단위라 목록에 넣으면 탐지 수천 건에서 응답이 수 MB가 된다),
  `POST /findings/status`(실제로 바뀐 항목만 반영). 화면이 고정 메뉴라 `@RequiresProgram` 없이 로그인만 필요 — 취약점 관리와 같은 기준이다. 누가 바꿨는지는 `statusChangedBy`.
  추적 규칙 초안은 `TraceRuleProposalController`(`/api/secure-code/trace-rule-proposals`): `GET ?status=`(기본 PENDING, 빈 값=전체, 최신 500건, 로그인만),
  `POST /apply {ids}`·`POST /dismiss {ids}`(**app-mng 권한** — 반영한 규칙은 모든 앱의 판정을 바꾼다. 업로드 점검과 같은 기준).
- **추적 규칙 확인**(`TraceRuleService.review` → `TraceRuleDrafter`·`FrameworkProfiler`·`TraceRuleChangePlanner`·`TraceRulesFileEditor`, 2026-10-08 개편):
  연계 추적 **전에**, 이미 받은 소스로 이 저장소의 프레임워크 장치와 설정 파일을 읽어 `trace-rules.yml` 초안을 만들고 지금 규칙과 비교해 변경(`TraceRuleChange`)을 만든다.
  새 시스템도 사용자 범위 키 후보를 찾아야 해서, 추적할 탐지가 없어도 소스는 읽는다(예전엔 `${}` 탐지가 있을 때만 확인했다).
  **결정론, AI 없음, 소스는 서버 밖으로 나가지 않는다.** 확인이 실패해도 점검은 지금 규칙으로 계속한다(알림만).
  - **나누는 기준 — 잘못 반영했을 때 무엇을 잃는가**(`TraceRuleChange.Type.automatic`):
    **바로 반영**(파일을 고치고 그 점검의 추적부터 씀, `AUTO_APPLIED`로 기록) — 판정을 엄격하게 하는 변경(기존 장치의 키 중 이 저장소 코드가 **세션 값이 아닌 값**을
    넣는 것으로 확인된 키 빼기)과 판정에 쓰지 않는 기록(프레임워크 구조). 틀려도 오탐이 늘 뿐이다.
    **확인 대기**(`PENDING`, 사람이 코드 점검 화면에서 반영) — 새 장치·키 추가, 첫 파라미터 조건 변경, 로그인 정보 타입·getter 접두어 추가. 틀리면 진짜 취약점이
    조용히 LOW가 된다(CRM `regPgmId` — 클라이언트가 보낸 statement 앞 6자리인데 손으로 쓴 설정에 세션 키로 들어가 있었다). 사용자 범위 키 추가는 엄격한 쪽이지만
    탐지가 한꺼번에 늘 수 있어 같이 묻는다.
  - **규칙은 여러 시스템이 같이 쓴다** — 다른 시스템에서 넣은 키를 이 저장소 코드에서 못 찾았다고 빼지 않는다(같은 어노테이션이라도 시스템마다 넣는 키가 다를 수 있다).
  - 찾는 것(`TraceRuleDrafter`): `@Aspect` 클래스의 `@Before`/`@Around`와 **XML `<aop:config>`의 before·around**(`FrameworkProfiler.xmlAdvices` — bean id → 클래스,
    컴포넌트 이름이면 첫 글자 대문자, `pointcut-ref` 펼침. after 계열은 요청 값을 못 바꿔 빼고, 어드바이스 메서드를 소스에서 못 찾으면 안내만) 포인트컷의
    `@annotation(X)` → 어노테이션, `args(request, ..)` → 첫 파라미터 조건. 어드바이스 본문에서 우리 메서드 호출을 따라가며(깊이 4) 요청 인자 기준 맵 경로
    (`arg.get("paramData")`, 맵 목록의 행)에 하는 `put("key", 값)` → 덮어쓰는 위치·키. **값이 세션에서 온 것만 키로 넣고** 아닌 것은 "세션 값 아님"으로 근거에만 남긴다.
    `(T) session.getAttribute(...)`의 T → 로그인 정보 타입, T의 getter(필드 이름으로도 — Lombok) 카멜 단어 경계 공통 접두어 → 로그인 getter 접두어.
    **사용자 범위 키 후보** = 위 장치가 세션 값으로 넣는 키와, 서비스·컨트롤러가 로그인 정보로 직접 넣는 키(`param.put("compCd", user.getLoginCompCd())` —
    값이 세션 `getAttribute`·세션에서 꺼낸 타입의 getter·로그인 getter 접두어로 시작하는 메서드 반환값. `TraceRuleDrafter.loginPuts`) 중 매퍼 SQL 조건 자리
    (WHERE·ON·HAVING)에 쓰인 것(값 자리만이면 등록자 기록이라 후보가 아니다). 서비스가 넣는 키는 근거에 SQL 위치와 put 줄을 함께 보여준다.
    지역 변수의 초기값은 따라가지만, 로그인 정보를 우리 메서드의 반환값이나 필드로 옮긴 뒤 넣으면(타입·이름으로 알 수 없을 때) 놓칠 수 있다.
    `HttpServletRequestWrapper` 상속·위치가 두 단계 이상(`paramData.sub`)인 장치는 설정으로 표현하지 못해 안내만 남긴다.
  - **프레임워크 구조**(`FrameworkProfiler.profile`): 빌드 파일(pom.xml·build.gradle — Spring Boot 버전, 웹·영속성·AOP·세션·보안 의존성, 아티팩트 이름 전체가 맞을 때만),
    web.xml(DispatcherServlet·Struts·필터·session-config), Spring XML(`<aop:config>`·`<aop:aspectj-autoproxy>`·`<mvc:annotation-driven>`·`<mvc:interceptors>` 빈·
    SqlSessionFactoryBean·SqlMapClientFactoryBean), MyBatis/iBatis 설정, application/bootstrap yml·properties(mybatis 설정, 세션 저장소 종류 등 정해 둔 키만 값을 읽음 —
    비밀값이 섞여 있다), 소스(`@SpringBootApplication`·`@Aspect`·`@EnableAspectJAutoProxy`·인터셉터·필터·요청 래퍼, `addInterceptors`). XML 주석 안은 뺀다.
    근거에 **줄 번호를 넣지 않는다** — 코드 몇 줄 바뀐 것으로 파일이 다시 쓰이지 않게. 설정 파일을 읽으려고 `MybatisDollarTracer.readSources`가 .java·.xml에 더해
    `FrameworkProfiler.isConfigFile`(application·bootstrap yml/properties, build.gradle)도 읽는다. 시스템별로 `frameworks.<시스템명>`에 쓴다.
  - **파일 고치기**(`TraceRulesFileEditor`, 순수): YAML을 통째로 다시 쓰지 않고 바꿀 줄만 고친다 — 주석이 "왜 이 키를 뺐나" 같은 판단 기록이라 지우면 안 된다.
    고친 곳 위에 `# 날짜 자동 반영|반영 사용자: … — 근거` 주석을 단다. 고친 결과를 다시 읽어 "지금 규칙 + 변경"과 같은지 확인하고 다르면 쓰지 않는다
    (그래서 세션 덮어쓰기 `keys`는 `[a, b]` 한 줄 모양이어야 한다). 로그인 정보 이름·사용자 범위 키 추가는 공통 목록이 아니라 그 변경을 만든 시스템의
    `systems.<시스템명>` 아래 목록에 넣는다(섹션·시스템·목록이 없으면 만들고, 여러 줄·한 줄 목록 모두 된다. 공통에 이미 있으면 넣지 않는다).
    이 변경의 같은 변경 키(`TraceRuleChange.key`)에도 시스템이 들어가 한 시스템에서 무시해도 다른 시스템에서는 다시 묻는다. `frameworks`는 서버가 쓰는 섹션이라
    통째로 다시 쓰고 항상 맨 끝에 둔다. 파일 쓰기는 임시 파일 → 바꿔 끼우기, 원래 줄바꿈(CRLF/LF) 유지, 점검과 화면 반영이 동시에 쓰지 않게 한 번에 하나.
    **서버가 저장소의 파일을 고치므로 사람이 git으로 확인·커밋한다.**
  - **확인 대기 저장**(`TraceRuleProposal`): 같은 변경(`TraceRuleChange.key` — 근거 줄 번호는 빼서 코드가 밀려도 같다)이 다시 나오면 한 건으로 묶고 마지막 확인 시각만 바꾼다.
    사람이 무시(`DISMISSED`)한 변경은 다시 묻지 않는다. 같은 앱을 다시 점검했을 때 안 나온 대기 변경은 `OBSOLETE`. 반영할 때는 저장해 둔 변경(JSON)을 그대로 다시
    적용한다 — 모든 변경은 두 번 적용해도 같아(이미 있는 키 더하기·없는 키 빼기는 그대로), 파일 쓰기 뒤 DB 저장이 실패해 다시 반영해도 규칙이 꼬이지 않는다.
    하나라도 파일에 못 쓰면 아무것도 반영하지 않는다. 반영한 규칙은 다음 점검부터 쓰인다.
  - 점검 완료 알림(`traceNote`): 자동으로 고친 판정 규칙(구조 기록 제외), 확인 대기 건수와 "반영하면 판정 N건이 바뀜"(`TraceRuleDraftPreview.changes` — 지금 규칙과
    대기 변경을 반영한 규칙으로 추적을 한 번 더 돌린 차이, `${}`와 사용자 범위 판정 모두. 새로 생기는 사용자 범위 판정은 위험한 것만 센다). 대기가 있을 때만 한 번 더 돌린다.
  - 처음(2026-10-02)엔 코드 점검 화면에 "초안" 버튼·모달로 두었다가 "규칙은 프레임워크마다 한 번이면 되고 설정 관리자용"이라 점검 때 확인해 로그에만 초안을 남기게
    바꿨다(10-06). 새 시스템을 넣을 때마다 로그의 YAML을 손으로 옮겨야 해서, 엄격한 쪽은 자동으로·느슨한 쪽은 화면 승인으로 다시 바꿨다(10-08).
    화면은 코드 점검의 "추적 규칙 초안"(확인 대기 건수 표시) 모달 — 대기 목록·근거·판정 영향, 반영/무시, "처리된 것도 보기".
- **규칙셋 버전**은 `rules/*.yml`과 함께 `trace-rules.yml`의 **판정에 쓰는 부분**(`TraceRulesFileEditor.judgmentPart` — `frameworks` 섹션 제외, 줄바꿈 정리)도 해시한다
  (`RuleSetLoader.load(rulesDir, extraContents)`) — 추적 규칙이 바뀌면 같은 코드도 판정이 달라져서 점검 이력에서 그 이유를 추적할 수 있게. 구조 기록만 바뀌면 버전은 그대로다.
  점검 중 규칙을 자동으로 고쳤으면 고친 규칙으로 버전을 다시 계산해 이력에 남긴다.
- **화면:** 사이드바 "시큐어코딩" 구역의 고정 메뉴 **코드 점검**(`secure-code-scan` — 앱별 점검 버튼·마지막 점검·점검 이력)과
  **코드 점검 결과**(`secure-code-mng` — 탐지 그리드, 처리여부 select·비고 저장, 제목 옆 "총 N건"(밑줄·손 모양 커서, 마우스를 올리거나 키보드 초점이 가면 항목별 건수를 공통 그리드(`Grid.render`, 부모를 `.grid-wrap`으로 둬 숨겨진 상태에서 높이 계산을 하지 않게)로 띄움 — 예전엔 제목 아래 한 줄에 모든 항목을 나열해 항목이 많으면 여러 줄로 꺾였다), 상세 모달의 규칙 id·줄 번호·강조 코드 조각과 CWE 링크(규칙 id는 내부 식별자라 그리드 열에 두지 않고 상세에만 — 무슨 약점인지는 항목·CWE 열이 보여준다),
  `${}` 탐지의 "연계 판정" 열(뱃지 색은 등급과 같은 기준, 열에는 판정만 보이고 대상 식·근거는 툴팁, 상세 모달 뱃지에는 매퍼 판정의 대상 식을 붙임 — "서버가 세팅 · ${loginBrndzCd}". 한 줄에 `${}`가 여럿이면
  탐지도 여럿인데 위치·항목이 같아 어느 행이 어느 값의 판정인지 구분되지 않았다. `SecureCodeFindingView.traceTarget`이 근거 마지막 줄에서 꺼낸다)과 모달의 근거 경로 목록(코드가 붙은 걸음은 밑줄 — 누르면 그 줄 앞뒤 3줄을 펼친다), "AI 판별" 열(취약 (AI) 빨강·확인 필요 (AI) 노랑·
  오탐 의심 (AI) 회색·판별 대기 파랑, 대상이 아니면 빈칸)과 모달의 신뢰도·이유·"참고 의견" 안내).
  APP·처리여부는 서버에서, 심각도·항목·CWE·파일은 받은 목록을 화면에서 거른다. CWE는 번호로 정확히 비교한다("89"·"CWE-89" 모두, 쉼표로 여러 개 — 부분 일치면 89가 CWE-189까지 걸린다). 모달을 열 때 `/findings/{id}/code`로 조각·근거 코드를 받아, 조각은 높이 420px로 묶고 걸린 줄이 보이게 스크롤한다. 코드 조각은 전부 textContent로 그린다.
- **규칙(45개 / 22개 파일, 행안부 7개 분류 중 시간 및 상태를 뺀 6개 — 2026-10-07 인가 후보 규칙 1개 폐기, iBatis `$값$` 규칙 1개 추가):** 2026-10-02에 아래 기존 규칙에 더해 추가한 것 —
  입력데이터 검증: 경로 조작(요청값→파일 경로 taint ERROR, 다운로드 응답 안의 변수 경로 WARNING — `path-traversal.yml`), XXE(외부 개체를 막는 설정 없이
  만든 XML 파서 WARNING — `xxe.yml`), 오픈 리다이렉트(`open-redirect.yml`), LDAP 삽입·XML(XPath) 삽입·코드 삽입(ScriptEngine·SpEL·`Class.forName`)·
  HTTP 응답분할(`injection.yml`, 앞 셋 ERROR·응답분할 WARNING). **모든 taint 규칙**(기존 명령어 삽입·SSRF·`xss-java` 포함)의 출처에
  `HttpServletRequest` 값과 Spring 요청 파라미터(`@RequestParam`·`@PathVariable`·`@RequestHeader`·`@RequestBody`)를 둔다.
  오픈 리다이렉트·SSRF는 **앞부분이 고정 호스트·경로인 문자열 연결**(`"https://host/..." + 값`, `상수 + "/..." + 값`)을 sanitizer로 뺀다 — 요청값이 쿼리에만
  들어가 대상이 바뀌지 않는다. `"/" + 값`(→ `//evil.com`)과 `상수 + 값`(→ `https://gw.com@evil.com`)은 호스트를 바꿀 수 있어 그대로 잡는다.
  SSRF의 WARNING 규칙(`kisa-ssrf-dynamic-url`)도 같은 기준으로 고정 호스트 연결을 뺀다.
  **실측(2026-10-02):** CRM_BACK은 Spring 출처를 넣어도 114 → 114(컨트롤러가 맵을 서비스로 넘기고 위험 호출은 서비스 안이라 한 메서드 taint로는 이어지지 않는다).
  ext-api는 `/proxy-image?src=` → `webClient.get().uri(src)` SSRF 1건을 새로 잡았다(실제 위험). 처음엔 `KAKAO_APP_GATEWAY + "/kakao/...?data=" + 값`
  리다이렉트 5건과 고정 호스트 호출 1건을 오탐으로 잡아 위 sanitizer를 넣었다(192 → 186).
  보안기능: 인증서·호스트 이름 검증 끄기(`tls-validation.yml`, ERROR), RSA·DSA·DH 2048비트 미만·비밀번호의 솔트 없는 해시(`weak-key-salt.yml`),
  주석 안의 비밀번호·키(`hardcoded-secret-comment.yml`, generic — 값 뒤에 `(`·`.`이 이어지면 주석 처리된 코드라 빼고, `${}`·`ENC(...)`도 뺀다. id에
  `hardcoded-secret`이 들어가 코드 조각에서 값이 가려진다 — `SecureCodeSnippetBuilder.COMMENT_SECRET`).
  에러처리: `printStackTrace`, 컨트롤러가 예외 메시지를 응답에 싣기, 빈 catch(변수 이름 `ignored`면 제외) — `error-handling.yml`, 모두 WARNING.
  코드오류: 역직렬화(`ObjectInputStream.readObject` WARNING — `ObjectInputFilter`면 제외, XMLDecoder·Jackson 기본 타이핑·`@JsonTypeInfo(Id.CLASS)`·제한 없는 XStream ERROR — `deserialization.yml`).
  캡슐화: 싱글톤 빈 필드에 요청 처리 중 값 쓰기(생성자·`@PostConstruct`·주입 setter 제외), 운영 코드의 main(`@SpringBootApplication` 제외, INFO),
  private 배열 반환·할당(`encapsulation.yml`). API 오용: 호스트 이름(DNS)으로 보안 판단(`api-misuse.yml`). XSS에 Vue `v-html`·React `dangerouslySetInnerHTML`·
  Angular `[innerHTML]`(`xss.yml`), innerHTML 규칙 대상에 .vue/.jsx/.ts/.tsx 추가.
  패턴으로 확정할 수 없는 항목(널 역참조·자원 해제·경쟁조건·반복 인증 제한·취약한 비밀번호 허용 등)은 무료판 Semgrep으로는 오탐만 많아 넣지 않았다.
  **실측(2026-10-02, CRM_BACK, 45개):** 117건(+13) — 인증서 검증 끄기 2(`HttpsUtils` — `TrustSelfSignedStrategy`+`NoopHostnameVerifier`, TLSv1·1.1 허용),
  RSA 1024비트 1(`RSAKeyPairGenerator`), XXE 1(업로드 엑셀을 읽는 `XLSX2CSV`의 SAX 파서), 주석 안 평문 DB 비밀번호 3(dev·local·prod 설정),
  빈 catch 2, printStackTrace 1, 남은 main 1, private 배열 2. 주석 규칙은 처음에 주석 처리된 코드(`secretKey = Keys.hmacShaKeyFor(...)`) 3건을 잡아 고쳤다.
  기존 규칙 —
  SQL 삽입(MyBatis `${}` — 매퍼로 보이는 xml만, XML 주석 안은 제외·CDATA 안은 잡음, 문자열 연결 SQL 실행),
  XSS(`th:utext`, JSP `<%= %>`·`escapeXml="false"`, JS `innerHTML` — `xss.yml`, 요청값을 응답에 직접 쓰기 — `xss-java.yml`),
  운영체제 명령어 삽입(요청값→`exec`/`ProcessBuilder` taint는 ERROR, 변수 명령 실행 지점은 WARNING),
  SSRF(요청값→`URL`/`RestTemplate`/`WebClient`/`HttpRequest` taint는 ERROR, 변수 주소 호출 지점은 WARNING),
  파일 업로드(`getOriginalFilename()`→저장 경로 taint는 ERROR — `FilenameUtils.getName/getExtension`을 거치면 제외, 저장 지점(`transferTo` 등)은 WARNING 검토 목록),
  하드코드된 중요정보(Java, 설정 파일 — `${}` 참조와 Jasypt `ENC(...)`는 제외, 복호화 키 `jasypt.encryptor.password`는 잡음), 취약한 암호, 부적절한 난수.
  규칙 메타데이터에 행안부 분류·항목명·CWE. 행안부 항목 **번호**는 원문 확인 전이라 넣지 않았다.
  taint 규칙은 무료판 Semgrep 한계로 **한 메서드 안에서만** 흐름을 본다 — 다른 메서드를 거친 입력은 WARNING 규칙(위험 호출 지점)으로만 잡힌다.
  **인증/인가(`authz.yml`, 4개):** 권한을 요청 값으로 판단(`param.get("isAdmin")`, `getParameter("role")` 등 — ERROR, CWE-807),
  Spring Security 전체 허용(`anyRequest().permitAll()`)·CSRF 끔·특정 계정명 하드코딩 비교(WARNING). 규칙에 특정 시스템의 어노테이션·클래스 이름을 넣지 않는다.
  사용자 범위(회사·브랜드·사용자) 조건의 값을 클라이언트가 정할 수 있는지는 패턴이 아니라 연계 추적이 판정한다(6-1-b, `kisa-authz-client-user-scope`).
- **실측(2026-10-01, CRM_BACK, 인증/인가 규칙 추가 후 22개):** 탐지 104건(+18) — 권한 요청 값 판단 3(`Crc020Service`의 `isAdmin`, 결재 분기),
  permitAll 1·CSRF 끔 1(`FrameWebSecurityConfig`), 사용자 범위 누락 후보 13(이 후보 규칙은 2026-10-07 폐기 — 6-1-b).
- **실측(2026-10-02, CRM_BACK, `${}` 연계 추적):** Semgrep `${}` 60건과 추적 판정 60건이 (파일, 줄, 줄당 개수)까지 일치, 추적 약 2초.
  클라이언트 값 14(`WHERE ${saleQuery}`·`${custQuery}`·`${customerQuery}` — 서버가 세팅하지 않는 SQL 조각, 테이블명 `${ym}`, `/common/saveOne`으로 실행되는
  `${sortOrd}`, `<otherwise>` 안의 `${type}`), 공통 경로로 우회 가능 33(`brndzCd`·`tableNm` — 서비스는 로그인 정보·상수로 세팅), 세션 덮어쓰기 7·서버 세팅 4
  (`loginBrndzCd`), XML 결정 2(`<when test="type == 'kakao'">`), 판정 불가 0. 클라이언트가 구문 id를 정하는 공통 실행 경로가 16개
  (`/common/selectList`·`saveOne`·`deleteOne`·`process`·`procedure`, `/cra040/upsertForm`, `/syb020/delete` 등) — 여기에 statement 허용 목록을 걸면 우회 33건이 LOW가 된다.
- **실측(2026-10-01, CRM_BACK, 규칙 17개):** 파일 168개 약 11초, 탐지 86건 — MyBatis `${}` 60, 난수 9, 설정 비밀값 6(AWS SES access/secret key, dev·local·prod),
  파일 업로드 저장 지점 4·원래 파일명 경로 2(Crc020Service·Crd010Service), SSRF 변수 주소 2(`callUrl`·`batchUrl` — 설정값이면 오탐), Java 비밀값 2, SHA-1 1.
  DB 비밀번호 9건은 Jasypt `ENC(...)`였다 — 처음엔 규칙이 이를 몰라 평문으로 잡았고, 코드 조각이 값을 가려(`****`) 화면만 보고는 구분할 수 없었다.
  `${}`는 동적 테이블명(`SU_MEM_INFO_${brndzCd}`)·Java에서 만든 WHERE 조각(`${saleQuery}`)·정렬값이 섞여 사람 검토가 필요하다.
- **홈 대시보드:** 두 기능을 좌우 카드로 나란히 둔다(`home.html` `.domain-card` — 조치할 건수 하나를 크게, 비율 둘을 작게, 앱별 TOP 5 막대는
  `fragments/app-bars.html` 공통). 1100px 아래면 위아래로. 시큐어코딩 수치는 `SecureCodeFindingService.getDashboard`(지워진 앱 제외, 탐지가 없으면
  비율 대신 "-"). 카드의 "… ›" 버튼은 사이드바 메뉴를 대신 눌러 탭으로 연다(카드가 바뀌어도 되게 `#homePanel`에 위임으로 건다).
  **자동 새로고침**(1분, 체크박스로 끄고 켬, 상태는 `localStorage` `home.autoRefresh`): 홈은 탭 셸이라 페이지를 다시 읽으면 열린 탭이 전부 닫히므로,
  `/`를 다시 받아(`fetch(..., {silent:true})` — 스피너 없음) 카드 영역(`.overview`)만 바꿔 끼운다. 수치를 JS로 다시 그리지 않아 화면 모양은 템플릿 한 곳뿐이다.
  홈이 보일 때만 돌고(다른 탭·가려진 브라우저 탭이면 쉼), 다시 보일 때 주기가 지났으면 바로 갱신한다. 실패하면 이전 수치를 두고 "갱신 실패 시각"을 경고색으로,
  세션이 끝나 로그인 페이지로 리다이렉트되면 창 전체를 로그인으로 보낸다. 켜 둔 채 홈을 띄워 두면 요청이 계속 가서 세션 유휴 만료가 일어나지 않는다.

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

**fix-plan의 pom.xml은 AI로 나가는 유일한 저장소 원문이라 비밀값을 가려서 보낸다**(`SecretMasker`, `FixPlanService.toTarget`). 가리는 것: 이름이 비밀값처럼
보이는 XML 요소 값(`<db.password>`, `<storepass>` 등), URL 계정 정보(`https://user:pass@`), `password=`류 키=값(JDBC URL·`-D` 인자), 형식이 알려진 토큰
(AWS·GitHub·GitLab·Slack·JWT·개인키 블록). `${프로퍼티}` 참조는 두고, 애매하면 가린다. 자리표시자는 `__MASKED_SECRET_<태그>_<번호>__` —
태그는 비밀값을 뺀 원문의 해시 앞 8자리다(비밀값 자체의 해시는 보내지 않는다 — 짧은 비밀번호는 해시로도 역추적된다). AI가 돌려준 pom은
`saveFixPlan`이 지금 스냅샷 pom을 다시 가려 얻은 대응표로 되돌린다. 보낸 뒤 재스캔으로 pom이 바뀌었으면 태그가 달라 되돌리지 않고 자리표시자를 남긴다
(엉뚱한 값을 넣지 않게, 로그 WARN). 프롬프트(`fix_plan.system.md`)는 자리표시자를 그대로 두라고 지시한다. dependency:tree는 좌표뿐이라 가리지 않는다.
실제 pom(CRM, 이 저장소)에서는 가린 값 0개·되돌림 일치.

AI에게 넘기는 근거도 마찬가지다. OSV에서 뽑은 `knownFixedVersions`가 있으면 AI가 설명 프로즈를
다시 해석해 유추하지 않도록 그 값을 최우선으로 쓰게 한다.

### 코드 점검 AI 판별 — stage 5 (`SecureCodeAiReviewService`)

시큐어코딩 점검 탐지가 진짜 취약한지 AI가 코드를 보고 판별한다. 라이브러리 단계들과 무관하고 같은 배치의 마지막에 돈다.

- **대상(`isTarget`):** OPEN이면서 (1) **연계 추적이 판정 불가로 남긴 것은 등급과 무관하게**(2026-10-08), (2) 연계 추적 판정이 없으면 등급이
  `ai.securecode.severities`(기본 HIGH)이거나 추가 규칙인 것. 연계 추적이 클라이언트 값(HIGH)·서버 세팅(LOW) 등으로 정한 건은 보내지 않는다 — AI는 마지막 수단.
  예전엔 판정 불가가 MEDIUM이라 기본 설정에서 대상이 안 돼, 엔진이 못 정한 탐지를 AI도 보지 않은 채 남았다(OWASP Benchmark cmdi —
  `exec(args, argsEnv)`의 환경 변수에 요청 헤더. 엔진은 배열 초기화를 알게 고쳤다). 판정 불가 근거("해석하지 못한 식 …")가 자주 나오는 모양은 엔진에 넣어
  결정론으로 옮긴다 — 한 번 넣으면 모든 시스템에 같은 판정이 나오고 AI 호출도 준다.
  **추가 규칙**(`ai.securecode.extra-rules`, 2026-10-07): 등급과 무관하게 넣는 규칙 — 기본 난수(`kisa-insecure-random`)·취약한 해시(`kisa-weak-crypto-hash`)·
  솔트 없는 해시(`kisa-hash-without-salt`)·XXE(`kisa-xxe-parser`), 모두 MEDIUM. 판정의 핵심이 "그 코드를 무엇에 쓰는가"(인증번호용 난수인지 화면 샘플링용인지,
  비밀번호용 SHA-1인지 캐시 키용인지, 파서가 클라이언트 파일을 읽는지)라 값 출처 추적으로는 못 정하고 메서드를 읽으면 대개 보인다 — 오탐이 가장 많은 묶음이다.
  `${}`·위험 호출 지점처럼 연계 추적이 판정한 묶음과 품질성 규칙(빈 catch 등)은 AI가 더할 정보가 적어 넣지 않았다.
  **하드코드된 비밀값 규칙(id에 `hardcoded-secret`)은 뺀다** — 점검 단계에서 값을 `****`로 가려 두므로 AI가 평문인지 `ENC(...)`·`${}` 참조인지 구분할 근거가 없다.
  첫 실행(2026-10-06, CRM_BACK·CRM_BATCH 30건)에서 22건이 비밀값 규칙이었고, 값을 못 본 채 거의 다 "취약(high)"을 냈다(규칙을 되풀이한 것뿐).
  그때 저장된 판별은 DB에 남아 있지만 `isReviewCurrent`가 비밀값 규칙이면 숨긴다. 나머지 8건(업로드 원래 파일명 2·`isAdmin` 3·TLS 2·RSA 1024 1)은 대상 그대로.
- **보내는 것:** 규칙·행안부 항목·CWE·등급·규칙 설명·파일 경로·줄, 코드 문맥(`aiContext`), 연계 추적 판정·근거.
  **코드 문맥이 없는 탐지는 대기열에 올리지 않고 다음 점검을 기다린다** — 대상 기준을 넓힌 직후 기존 탐지에는 문맥이 없는데, 화면용 조각으로 판별하면
  근거가 부족하고 다음 점검에서 문맥이 생기면 입력이 바뀌어 다시 판별(과금)된다. 화면은 이런 건도 "판별 대기"로 보이고 모달에 "코드 문맥이 아직 없으면 다음 코드 점검 뒤"라고 적는다.
  코드는 보내기 직전에 `SecretMasker`로 가린다(되돌릴 원문이 없어 대응표는 버린다). **소스 코드가 AI로 나가는 유일한 곳이다**(사내 정책 예외, 2026-10-06 승인,
  2026-10-07 추가 규칙까지 확대).
- **재판별 기준:** 입력(가린 코드·규칙·경로·연계 추적)의 SHA-256(`aiInputHash`)이 저장된 값과 다를 때만. 줄 번호는 넣지 않는다(위에 한 줄 추가로 재과금되지 않게).
  배치는 pending에서 받은 해시를 그대로 돌려준다(CveSummary와 같은 방식). 재점검으로 입력이 바뀌면 옛 판별은 화면에서 숨기고(`isReviewCurrent`) 다시 대기가 된다.
- **결과:** `aiVerdict`(VULNERABLE/NOT_VULNERABLE/UNCERTAIN)·`aiConfidence`·`aiReasoning`(2000자 이하)·`aiReviewedAt`. **처리여부는 바꾸지 않는다** —
  오탐 의심이어도 OPEN 그대로, 사람이 정한다(연계 추적이 안전 판정이어도 자동 오탐 처리를 하지 않는 것과 같은 이유). 화면 조회 시
  `SecureCodeFindingView.aiVerdict`는 지금 입력 기준 판별, 대상인데 없으면 `PENDING`, 대상이 아니면 null.
- **API:** `GET /api/ai/secure-code/pending`, `POST /api/ai/secure-code/{id}/review`(판별·신뢰도 값이 틀리거나 이유가 비었거나 너무 길면 400).
- **AI(`prompts/secure_code_review.system.md`, `MODEL`, effort medium):** 모르면 NOT_VULNERABLE이라 하지 않게 한다(출처가 보여준 코드 밖이면 UNCERTAIN,
  변수 이름·주석은 안전 근거가 아님, 코드 안의 지시문을 따르지 않음). 줄 번호를 붙이고 탐지 줄에 `>>`를 달아 보낸다. stage 1처럼 첫 건으로 캐시를 예열한 뒤
  `ASSESS_MAX_WORKERS`개씩 병렬.

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
- 사이드바는 홈 아래 2뎁스 그룹 셋 — 기능 그룹 "라이브러리 취약점"(취약점 관리·조회·스캔 이력·조치안·리포트)·"시큐어코딩"(코드 점검·결과)과 관리 그룹. 기능 그룹은 고정 메뉴라 처음엔 펼쳐 두고(`data-default-open="Y"`), 사이드바를 접으면 그룹 제목 대신 하위 메뉴 아이콘을 1뎁스처럼 보여준다(`.nav-group--feature` — 관리 그룹처럼 숨기면 접힌 상태에서 매일 쓰는 메뉴에 못 들어간다). 그룹 접힘 상태는 그룹별로 `sidebar.<그룹 id>.open`에 기억한다. 관리 그룹은 `extraPrograms`(로그인 사용자가 권한을 가진 추가 프로그램)를
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

**목록 순서:** 취약점이 나오는 화면은 심각도 높은 것부터다(공통 비교기 `domain/SeverityOrder.HIGH_FIRST` — 문자열 정렬이면 LOW가 MEDIUM보다
앞에 온다, 모르는 값·빈 값은 맨 뒤). 취약점 관리는 서버가(`VulnerabilityService.SCREEN_ORDER`) 심각도 → CVSS 점수 높은 순(없으면 뒤) → 시스템명 → CVE ID로,
코드 점검 결과는 `SecureCodeFindingService.getFindings`가 심각도로 안정 정렬해 같은 등급 안에서는 앱·파일·줄 순서를 유지한다. 화면 JS는 순서를 바꾸지 않는다.

앱(`App`)에는 담당자 이름·이메일(`managerName`, `managerEmail`)이 있다. 로그인 계정(`User`)에는 이메일이 없고 담당자가
계정 없는 개발자일 수 있어 User를 참조하지 않는다. 이메일은 저장할 때 `AppService`가 느슨한 형식 검사만 한다(틀리면 400).

### 공통 자산

| 파일 | 역할 |
| --- | --- |
| `/css/common-ui.css` | `:root` 변수, `.app-shell`, `.btn`, `.panel-head`, `.page-toolbar`, 코드·원문 블록(`.code-block` — 조치안 pom.xml, 코드 점검 조각. 줄마다 `.code-line > .code-no + .code-text`(flex — 긴 줄이 꺾여도 줄 번호 칸 아래로 안 파고든다), 탐지 줄은 `.hit`, 마우스를 올린 줄은 IDE처럼 줄 전체·줄 번호 강조), 모달(`.modal-backdrop`+`.open` / `.modal` / `.modal-actions`), 모달 안의 라벨|값 상세 표(`.detail-list` — 취약점 관리 상세보기·조치안), 상태 뱃지(`.badge.<코드값 소문자>` — 처리여부·심각도·스캔 결과·점프 폭·영향 분석 상태) 등 페이지 뼈대. 화면 공통 버튼은 항상 우측 상단 — 제목과 한 줄이면 `.panel-head`, 조회조건 영역이 있으면 그 위에 `.page-toolbar` |
| `/css/grid.css` | `.grid` 공통 모양. 헤더 높이(45px)와 본문 행 높이(32px)를 모든 그리드에서 고정한다 — 화면 `<style>`에서 행 높이를 덮어쓰지 않는다. 헤더는 `position:sticky`라 세로 스크롤 때 고정된다. 행 안의 버튼(취약점 조회 스캔, 취약점 관리 상세보기)은 `.btn.grid-btn` |
| `/js/grid.js` | **가상 스크롤(`Grid.render`의 `virtual: true`, 행 100개 이상일 때):** 보이는 범위 ± 20행만 tbody에 붙이고 위아래는 높이만 차지하는 빈 칸 행(`tr.grid-spacer`)으로 채운다 — 600행 표가 탭(iframe)을 다시 보일 때 전부 다시 배치되며 버벅였다(코드 점검 결과). 행(tr)은 전부 만들어 `tbody._gridAllRows`에 두고 붙였다 뗐다 해서 입력값이 남고, `getRows`·엑셀·복사·열 이동·현재 행 강조·엔터/방향키 이동(`neighborRow` — 화면 밖 행이면 스크롤해 붙인다)은 전체 행 기준이다. 행 높이 일정(32px)·table 부모가 스크롤 영역이라는 전제라 지금은 코드 점검 결과 그리드만 켠다. 숨겨진 탭에서는 높이가 0이라 계산하지 않고, 다시 보일 때(iframe resize) 맞춘다. (`Grid.copyText`는 그리드 밖에서도 쓰도록 공개한 클립보드 복사 — https가 아니면 execCommand 폴백. 조치안 pom.xml 모달이 쓴다) 컬럼 정의(`COLUMNS`)로 헤더·행·입력 셀까지 만드는 공통 그리드 렌더러. `renderHeader`가 tbody의 첫 안내 행("조회 중입니다...", colspan 자동)도 넣으므로 템플릿의 `<tbody>`는 비워 둔다. 행 데이터는 `getRows`/`getRow`(원본 row + 입력 셀 현재 값, `_rowIndex`/`_isNew`/`_selected`)로 읽고 `onRowClick(tr, row)`도 같은 값을 받는다. select 컬럼에 `display(value, label, row)`를 주면 평소엔 그 결과(뱃지 등)를 보여주고 셀을 누를 때만 select로 바뀐다(취약점 관리 처리여부). 또 table을 `.grid-scroll`로 감싸고 숫자 `width`를 최소 폭으로도 적용해, 화면보다 넓으면 가로 스크롤이 생긴다. `.grid-scroll`의 세로 한도(`max-height`)는 grid.js가 "그 영역 시작 위치부터 화면 아래 끝까지"로 계산해 넣어(헤더·행을 그릴 때, 창 크기 변경 때), 행이 많으면 페이지가 아니라 그리드 본문만 스크롤된다(최소 200px). 화면이 스크롤 영역을 직접 둔 경우(`.grid-wrap`, 취약점 관리)는 감싸지 않는다. **모든 그리드 공통으로** 클릭한 셀에 테두리(`td.cell-current`)를 그리고, 데이터 셀 우클릭 시 공통 메뉴(셀 복사 / 행 복사(탭 구분) / 엑셀 다운로드)를 띄운다 — 값은 화면에 보이는 값(입력 셀은 현재 입력값, select는 옵션 이름)이고 id 없는 컬럼(행 선택·버튼 열)은 행 복사·엑셀에서 빠진다. 입력 셀(에디터) 위에서도 같은 메뉴가 뜨고, 우클릭으로는 입력칸에 커서가 들어가지 않는다(mousedown 기본 동작 차단). 클립보드는 http(비보안 컨텍스트)면 `execCommand` 폴백. 헤더(th)를 드래그앤드롭하면 컬럼 순서가 바뀐다 — 화면이 넘긴 컬럼 배열을 제자리에서 바꾸므로(`moveColumn`) 재조회해도 유지되고 새로고침하면 원래 순서다. **그래서 화면 코드가 컬럼을 순번(`cells[i]`, `COLUMNS[i]`)으로 가정하면 안 된다** — 행 데이터는 항상 `col.id`로 읽는다 |
| `/js/zip-writer.js` | 외부 라이브러리 없는 무압축 zip 작성기 `ZipWriter.storedBlob([{name, data(Uint8Array)}], type)`. 파일명 UTF-8(표시 비트 켬), ZIP64 없음(65,535개·4GB 넘으면 예외). 엑셀 다운로드(xlsx-writer.js)와 코드 점검 폴더 업로드가 쓴다 — 처음엔 xlsx-writer.js 안에 있었는데 두 번째로 쓰게 되어 뺐다. `loading-overlay.html`이 xlsx-writer.js보다 먼저 싣는다 |
| `/js/xlsx-writer.js` | 외부 라이브러리 없는 최소 .xlsx 작성기(시트 XML을 `ZipWriter`로 묶음). `XlsxWriter.download(파일명, {sheetName, headers, widths, rows})`. 모든 셀을 문자열로 넣는다 — CSV면 엑셀이 버전 `1.10`을 숫자 1.1로 바꾼다. 헤더는 화면 그리드처럼 항상 가운데 정렬 + 배경 RGB(31,56,100)·흰 굵은 글꼴(`HEADER_FILL`). `loading-overlay.html`이 싣는다 |
| `/js/modal-drag.js` | 공통 모달(`.modal-backdrop` > `.modal`)을 첫 `h3`(제목줄)로 끌어 옮긴다. `transform`으로만 움직여 닫히면(`.open` 제거) 위치가 초기화되고, 제목줄이 화면 밖으로 못 나가게 막는다. 끌다가 백드롭 위에서 놓으면 생기는 click을 삼켜 "백드롭 클릭 = 닫기"가 오작동하지 않게 한다. `loading-overlay.html`이 싣는다 — **새 모달은 제목을 `h3`로 두기만 하면 된다** |
| `/js/code-highlight.js` | 외부 라이브러리 없는 코드 조각 구문 강조. `CodeHighlight.lines(text, CodeHighlight.languageOf(path))` → 줄마다 `{type, text}` 토큰. 언어는 확장자로 java·js·markup(xml/html/jsp — SQL 키워드, `#{}`, 위험 표시 `${}`)·config(properties/yml). 색은 `common-ui.css`의 `.code-block .tok-*`(IntelliJ 라이트 테마 색, 클래스 이름만 청록 — 검정이면 일반 글자와 구분이 안 됐다). `CodeHighlight.enableUsages(pre)` — 이름(`tok-ident`·`type`·`constant`·`function`, MyBatis `${}`·`#{}`는 안쪽 이름으로)을 누르면 그 블록에서 같은 이름을 모두 칠한다(`.tok-usage`, IntelliJ 사용처 강조). 다시 누르거나 이름이 아닌 곳을 누르면 지우고, 드래그로 고르는 중이면 칠하지 않는다. 화면은 토큰을 textContent로만 넣는다. 코드 점검 결과 상세보기(조각·연계 추적 걸음 코드)가 쓴다 |
| `/js/com-cd.js` | 공통코드로 select 옵션 채우기(그룹당 1회 캐시) |
| `/js/tabs.js` | 홈 화면 탭 |
| `/js/hotkeys.js` | 공통 펑션키 F3 조회 / F4 신규 / F5 삭제 / F9 저장 / F12 초기화. 버튼에 `data-hotkey="F3"`만 붙이면 되고, 버튼 글자 뒤 `[F3]` 표기도 이 파일이 자동으로 붙인다. `loading-overlay.html`이 싣는다 |
| `/js/search-form.js` | 조회영역 공통 렌더러 `SearchForm.render(container, fields, {onSearch})` → `values()`/`reset()`/`field(id)`/`matches(row)`/`ready`. `matches(row)`는 전체 목록을 받아 조회조건을 화면에서 거르는 화면(프로그램·사용자·공통코드 관리, 취약점 조회)이 쓴다 — text 필드마다 `row[field.id]` 부분 일치(대소문자 무시), 필드에 `match(value, keyword)`를 주면 그 함수로 비교한다. 화면은 `<section class="search-row" id="searchArea">`만 두고 label/input 마크업을 직접 쓰지 않는다 |
| `fragments/page-toolbar.html` | 화면 첫 줄 — 좌상단 프로그램명 + 우측 상단 공통 버튼. 값(`programNm`, `pageButtons`)은 `ViewController`가 넣는다. 버튼은 마크업에 쓰지 않는다(아래 "화면 공통 버튼" 참고) |
| `/js/page-buttons.js` | `PageButtons.bind({ btnSave: fn })` — 권한 때문에 안 그려진 버튼은 건너뛰고 핸들러를 건다. `loading-overlay.html`이 싣는다 |
| `fragments/loading-overlay.html` | 전역 스피너 + **CSRF 헤더를 붙이는 공통 fetch 래퍼**(`zip-writer.js`도 싣는다)(`init.silent: true`면 스피너 없이 — 홈 자동 새로고침 같은 백그라운드 갱신용) + `hotkeys.js`·`page-buttons.js`·`xlsx-writer.js`·`modal-drag.js` 로드 |

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
| `git.credentials[n].url-prefix` / `.username` / `.token` | 저장소 clone 인증 정보(`GitCredentialResolver`, 빈은 `GitConfig`). 저장소 주소와 경로 단위로 **가장 길게** 일치하는 항목을 쓴다(`.../crm`은 `.../crm2/...`에 안 걸림, 대소문자·끝 슬래시 무시). 일치하는 항목이 없으면 인증 없이 clone한다(공개 저장소). 서버 전체 토큰은 호스트 주소(`https://git.sejung.co.kr/`)를 url-prefix로 둔 항목이고, 그룹·저장소마다 토큰이 다르면 더 긴 url-prefix 항목을 추가한다 — 따로 "기본 토큰" 키는 없다. username이 비면 `oauth2`. url-prefix가 https가 아니거나 호스트가 `scan.allowed-repo-hosts`에 없거나 token이 비거나 같은 url-prefix가 두 번이면 **기동 실패**(조용히 인증 없이 clone하다 "저장소 없음"으로 실패하면 원인을 못 찾는다). 토큰은 대개 저장소가 아니라 서버·그룹 단위로 발급되고 비밀값을 DB에 넣지 않으려고 앱 관리(DB)가 아니라 설정 파일에 둔다. clone마다 어느 항목을 썼는지(url-prefix, 토큰 제외) 로그에 남는다. **예전 단일 키 `git.access.token`/`git.user.name`(2026-10-06까지)은 없앴다** — 남아 있으면 옮기라는 메시지로 기동을 멈춘다(어느 주소든 같은 토큰을 붙여 다른 호스트를 허용하는 순간 사내 토큰이 그쪽으로 나갈 수 있었다) |
| `maven.home` | `dependency:tree` 실행용 Maven 홈 |
| `claude.api.key` | AI 판단 / fix-plan / 설명 요약 / 영향 분석 / 코드 점검 판별 |
| `ai.internal.token` | 자바 ↔ 파이썬 배치 인증 (`SECURITY_MONITOR_AI_TOKEN`과 같은 값) |
| `ai.python.command` | 파이썬 실행 명령 (이 PC는 `py`) |
| `ai.assessor.script` | 배치 스크립트 경로 (`../ai/vuln_assessor.py`) |
| `ai.assessment.severities` | AI 판단 대상 등급 (기본 `HIGH,CRITICAL`) |
| `ai.securecode.severities` | 선택. 코드 점검 탐지 중 AI 판별 대상 등급 (기본 `HIGH`, 코드 점검 등급은 HIGH/MEDIUM/LOW). 연계 추적이 판정한 건과 하드코드된 비밀값 규칙은 등급과 무관하게 빠지고, 연계 추적이 판정 불가로 남긴 건은 등급과 무관하게 들어간다 |
| `ai.securecode.extra-rules` | 선택. 등급과 무관하게 AI 판별 대상에 넣는 규칙 id(쉼표 구분, 기본 `kisa-insecure-random,kisa-weak-crypto-hash,kisa-hash-without-salt,kisa-xxe-parser`, 비우면 없음). 연계 추적 판정·비밀값 규칙 제외는 같다 |
| `github.token` | 선택. 영향 분석이 GitHub Releases를 받을 때 쓰는 읽기 전용 토큰. 배치에 `GITHUB_TOKEN`으로 넘긴다. 없으면 토큰 없이 부른다 |
| `ai.auto-trigger.enabled` | 스캔 후 AI 배치 자동 실행 스위치의 **초기값**(기본 `true`, DB를 처음 만들 때만 쓰인다). 실제 스위치는 공통코드 `AI_CONFIG`/`AUTO_TRIGGER`의 사용여부로, 공통코드 관리 화면에서 바꾸면 재기동 없이 다음 스캔부터 적용된다(`ComCdService.isEnabled`). DB를 처음 만들 때만 이 값으로 심는다(파일 DB라 재기동해도 공통코드 값이 유지된다). 로컬은 `false`로 두면 과금 없이 스캔할 수 있다 |
| `securecode.semgrep.command` | 선택. semgrep 실행 파일(기본 `semgrep`). 기본값인데 PATH에 없으면 `ai.python.command`로 파이썬 Scripts 폴더를 물어 거기서 찾는다(`SemgrepRunner.findInPythonScripts` — 이 PC는 PATH에 없다). 직접 준 경로는 그대로 쓴다. `py -m semgrep`은 지원 중단됐다 |
| `securecode.rules-dir` | 선택. 코드 점검 규칙 폴더(기본 `../securecode/rules`) |
| `securecode.timeout-seconds` | 선택. 코드 점검 1회 제한시간(기본 600) |
| `securecode.trace-rules` | 선택. MyBatis `${}` 연계 추적의 시스템별 프레임워크 규칙 파일(기본 `../securecode/trace-rules.yml`) |
| `securecode.upload.max-bytes` | 선택. 코드 점검 소스 zip 업로드 크기 상한(바이트, 기본 524288000 = 500MB). 이 시스템의 유일한 파일 업로드라 멀티파트 상한 전체가 이 값이다 |
| `securecode.upload.max-extracted-bytes` / `securecode.upload.max-entries` | 선택. 업로드 zip을 푼 크기 합(기본 2GB)·파일 수(기본 20만) 상한 — 압축 폭탄 방지 |
| `scan.allowed-repo-hosts` | 앱 등록을 허용할 저장소 호스트 목록(쉼표 구분, 기본 `git.sejung.co.kr`). 다른 호스트를 쓰게 되면 여기서 늘린다 |

AI 배치 실행 로그는 종류별 파일에 이어 쌓인다(gitignore 대상) — 라이브러리 취약점 `backend/ai-assessor.log`, 시큐어코딩 `backend/ai-securecode.log`
(`AiAssessmentTriggerService.BatchKind` — 동시에 돌 수 있어 한 파일이면 두 실행의 줄이 섞인다). 진입점 인자: `vuln_assessor.py cve|securecode`(인자 없으면 둘 다, 사람이 직접 돌릴 때).
`/api/ai/status`는 종류별 상태 맵을 준다. 줄마다 `[YYYY-MM-DD HH:MM:SS][traceId]`가 붙는다(`_TimestampedStream`, traceback 포함). traceId는 실행마다 하나 — 서버가 띄우면 `AiAssessmentTriggerService`가 만들어 `SECURITY_MONITOR_TRACE_ID`로 넘기고 서버 로그의 "배치 실행 시작/종료" 줄에도 찍는다(사람이 직접 돌리면 파이썬이 만든다). 실행마다 `===== AI 배치 시작(시큐어코딩) =====`(괄호에 기능 이름) / `===== AI 배치 종료(exit=N) =====` 줄과 끝의 빈 줄이 남는다. 서버가 `PYTHONIOENCODING=utf-8`로 띄워 로그는 UTF-8이다(예전엔 윈도우 기본 cp949라 IDE에서 한글이 깨졌다).

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
- `SeverityOrderTest` / `VulnerabilityScreenOrderTest` — 심각도 정렬(알파벳순 아님, 모르는 값은 뒤), 취약점 관리 화면 순서(심각도 → CVSS → 시스템명 → CVE ID)
- `CveSummaryServiceTest` — 설명 요약 대기 판단(CVE ID 단위, 해시 비교, 최신 설명 선택)과 저장 검증
- `SemgrepReportParserTest` — Semgrep JSON 해석(규칙 id 접두어 제거, 역슬래시 경로, 심각도 변환, 경로 있는 오류만 분석 실패 파일)
- `DuplicateCweMergerTest` — 같은 줄·같은 CWE 다른 규칙은 추적 규칙 한 건(판정 등급 유지, 설명에 함께 걸린 규칙), 추적 판정이 없으면 묶음 최고 등급·규칙 id 순,
  같은 규칙 여러 번·다른 줄·CWE 없음은 그대로. `SecureCodeReconcilerTest`에 합쳐 빠진 기존 탐지(비고·사람이 정한 상태 유지·해결 건수 제외)
- `SecureCodeSnippetBuilderTest` — 지문(줄 밀림·들여쓰기 무관, 코드가 바뀌면 다름, 같은 코드 두 번은 순번), 조각(감싼 메서드·80줄 자름, 매퍼 XML은 감싼 구문, 못 찾으면 앞뒤 5줄), 연계 추적 근거 코드(걸음별 앞뒤 3줄, 동명 파일 고르기), 비밀값 가림, MS949 폴백, 저장소 밖 경로 차단,
  AI 판별 문맥(감싼 메서드 전체, 긴 메서드는 걸린 줄 가운데로 80줄·끝이면 당김, 자바가 아니면 앞뒤 15줄·비밀값 가림)
- `SecureCodeAiReviewServiceTest` — AI 판별 대상(결정론으로 못 정한 높은 등급, 판정 불가는 등급 무관, 비밀값 규칙 제외·남은 판별 숨김), 대기열(지워진 앱·판별 완료 제외), 코드가 바뀌면 옛 판별 숨김·재대기,
  줄 번호만 밀리면 재판별 안 함, 문맥 없으면 조각·비밀값 가림, 판별 값 검증, 처리여부는 그대로
- `SecureCodeReconcilerTest` — 재점검 비교(신규·유지·해결, 분석 실패 파일·빠진 규칙은 해결 안 함, 수동 상태 유지, 재발견 시 OPEN)
- `RuleSetLoaderTest` — 규칙 id·규칙셋 버전, 규칙 0개·폴더 없음은 실패, 실제 규칙 폴더 읽기
- `MybatisDollarTracerTest` — `${}` 연계 추적(상수·삼항·모든 분기 상수 반환은 서버 세팅, else 없는 조건부 세팅은 클라이언트 값, XML 상수 비교·bind,
  세션 덮어쓰기는 container 안의 키만·첫 파라미터 조건, 공통 실행 경로 우회, List 실행 제외, 다른 프레임워크 규칙은 설정만으로, 규칙 없으면 클라이언트 값, 설정 파일 읽기, XML 줄 번호·주석 제외)
- `UserScopeTraceTest` — 조건·값 자리 구분(INSERT 값/INSERT…SELECT WHERE, UPDATE SET/WHERE·SET 안 서브쿼리, `<where>`·`<set>`·`<trim>`, MERGE ON·
  ON DUPLICATE KEY UPDATE, 주석 속 키워드 무시, 키워드 없는 조각은 조건), 값 자리의 키는 인가 판정에서 빠짐, 맵을 돌려주는 유틸 메서드 추적, 사용자 범위 판정(클라이언트가 보낸 키는 클라이언트 값, 설정한 장치가 덮어쓰면 안전·안 덮어쓰는 키는 클라이언트 값, 서비스가 로그인 정보로
  넣어도 공통 실행 경로로 우회, 키가 매퍼에 없으면 판정 없음·알림용 플래그, 설정 없으면 판정 안 함, 위험한 판정만 탐지·지문 고정, `#{}` 첫 이름 키, 설정 읽기) —
  CRM이 아닌 가상 시스템 설정으로 검증한다
- `SecureCodeRuleRetirementTest` — 폐기 규칙의 미조치 탐지를 조치완료로 정리(사람이 쓴 비고 유지, 사람이 정한 상태는 그대로), 폐기 규칙이 규칙 폴더에 없음
- `SecureCodeFindingViewTest` — 매퍼 판정 근거 마지막 줄에서 대상 식 꺼내기(`${}`·`#{}`·iBatis `$값$`·`#값:VARCHAR#`), 매퍼 판정이 아니면 없음
- `IbatisTraceTest` — sqlMap 읽기(치환·바인딩·표시 원문, 주석 제외, `<isEqual compareValue>` XML 결정, `prepend` WHERE/SET 자리, namespace 없는 id),
  Spring 없는 옛 코드(`request.getParameter` → 맵 → `getSqlMapClientTemplate().queryForList`)의 `$값$`·사용자 범위 `#값#` 판정
- `DollarTraceMergerTest` — 판정별 등급 재매김·근거·지문 유지, 한 줄 여러 `${}`는 순서로, 줄 안 개수가 다르면 Semgrep 등급 유지, 다른 규칙은 그대로
- `SinkTracerTest` — 서비스의 위험 호출을 컨트롤러까지 따라가 판정(요청값 주소 CLIENT, `@Value` 주소·고정 호스트 + 쿼리 SERVER_SET, 원래 파일명 저장 CLIENT,
  UUID 파일명 SERVER_SET, 상수 명령 SERVER_SET), 판정으로 등급 재매김(CLIENT HIGH·서버 LOW), 호출을 못 찾은 탐지·다른 규칙은 그대로, 지문 유지
- `FrameworkProfilerTest` — 빌드 파일·web.xml·Spring XML·application.yml·소스에서 구조(주석 안 제외, 비밀값 안 남김, 근거에 줄 번호 없음), 같은 저장소면 같은 결과,
  XML AOP 어드바이스(bean id → 클래스, pointcut-ref 펼침, after 제외)
- `TraceRuleChangePlannerTest` — 새 시스템은 장치·로그인 정보·범위 키가 확인 대기·구조는 바로 반영, 세션 값 아닌 키는 자동 제외, 이 저장소에서 못 찾은 키는 안 뺌,
  키 추가·첫 파라미터 조건은 대기, 같은 구조면 변경 없음, 두 단계 위치는 안내만, 두 번 적용해도 같음, JSON 왕복, 줄 번호가 달라도 같은 키
- `TraceRulesFileEditorTest` — 키 빼기·장치 추가·한 줄/여러 줄 목록 더하기에서 주석 유지·근거 주석, 구조 섹션은 맨 끝에 시스템별로·다시 쓰면 교체, 판정 부분 해시는 구조와 무관,
  이미 반영된 변경은 그대로, 빈 파일, 예상과 다른 모양이면 실패, 첫 파라미터 조건 바꾸기·없애기, 실제 trace-rules.yml에 써도 규칙 유지
- `TraceRuleDrafterTest` — AOP 포인트컷·호출 추적으로 세션 덮어쓰기 후보(세션 값 아닌 키는 따로), 이름 붙은 포인트컷·요청 맵 자체 덮어쓰기, AOP 없음 안내, XML AOP 후보·
  어드바이스 메서드 없음 안내, 사용자 범위 키 후보(조건 자리만, 서비스가 로그인 정보로 넣는 키 — 형 변환 없이 꺼내도 getter 접두어로),
  반영 시 판정 변화, 카멜 공통 접두어
- `GitCredentialResolverTest` — 저장소 주소별 인증 선택(가장 긴 일치, 경로 단위 경계, 대소문자·끝 슬래시 무시, 호스트 항목이 서버 전체 토큰·다른 호스트엔 안 붙음,
  설정 없으면 인증 없음, 빈 사용자 이름은 oauth2, 로그 문자열에 토큰 없음, 잘못된 설정·중복 url-prefix는 기동 실패) / `GitConfigTest` — `git.credentials[n].*` 키가
  실제로 읽힘, 예전 단일 키가 남아 있으면 기동 실패, 설정 없으면 인증 없음
- `SourceArchiveExtractorTest` — 업로드 zip 압축 해제(최상위 폴더 벗기기·안 벗기기, `../`·절대 경로·드라이브 문자 전체 거부, 풀린 크기·파일 수 상한, MS949 한글 파일명,
  맥 압축 부산물 건너뜀·소스 0개 집계, zip이 아니면 안내) / `AppServiceTest` — 업로드 앱은 저장소 값을 지우고 검증 생략, Git 앱은 저장소 검증·브랜치 필수, 모르는 출처 거부 /
  `SchemaMigrationTest` — 메모리 H2에서 NOT NULL 풀기(두 번 돌려도 됨) / `SourceArchiveExtractorBrowserZipTest` — 화면 폴더 업로드가 만드는 zip(zip-writer.js와
  같은 바이트 배치: 무압축·UTF-8 표시)을 서버가 풀고 폴더 이름을 벗김
- 화면 JS(grid.js 가상 스크롤 등)는 자동 테스트가 없다 — 가상 스크롤은 jsdom으로 붙는 행 수·전체 행·입력값 유지·신규/삭제·강조를 한 번 확인했지만(배치가 없어 스크롤 위치 계산은 못 봄) 저장소에 테스트로 남기지 않았다.
- `SecretMaskerTest` — pom 비밀값만 가림(버전·좌표·`${}` 참조는 남김), AI 결과 되돌림, 보낸 뒤 pom이 바뀌면 되돌리지 않음, 비밀값 없으면 원문 그대로

규칙 자체는(사용자 범위 판정은 Semgrep 규칙이 아니라 위 Java 테스트로) `securecode/rules/`의 예제 파일로 `securecode/test_rules.py`(규칙 파일마다 `semgrep --test`)가 검증한다(22개 규칙 파일 통과).

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
- `secure_code_review.system.md` — 코드 점검 탐지 판별(stage 5). 행안부 항목별 판별 기준, 모르면 UNCERTAIN. 라이브러리용 `rules/`와 무관해 include하지 않는다
- `ai/release_note_sources.json`(프롬프트가 아니라 수집 규칙) — groupId별 공식 문서 URL
- `rules/` — `false_positives.md`, `maven_strategy.md`, `version_matching.md`
