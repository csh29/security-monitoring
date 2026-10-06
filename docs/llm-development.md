# llm-development.md — 개발용

**이 문서는 "어떻게 작업해야 하는가"(규범)만 적는다.**
코드를 쓰거나 고치기 전에 읽는다. 시스템이 지금 어떻게 되어 있는지(사실)는
[`llm-analysis.md`](llm-analysis.md)에 있다 — **작업 전에 그쪽을 먼저 읽는다.**

---

## 1. 빌드 / 실행 / 테스트

작업 디렉터리는 `backend/`다.

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

### 파이썬은 반드시 `py`

이 PC에서 `python` / `python3`은 Microsoft Store 스텁이라 **exit 49로 죽는다.** 실제 인터프리터는
`py` 런처뿐이다. 문서·주석에 `python xxx.py`로 적혀 있어도 `py xxx.py`로 바꿔 실행한다
(`py -m pip`, `py -c "..."` 동일).

경로에 한글이 포함되므로(`C:\ai 과제\...`) 셸 명령에서는 항상 큰따옴표로 감싼다.

```bash
py -m pip install -r ../ai/requirements.txt
```

파이썬 쪽 테스트는 릴리스 노트 수집기(`ai/release_notes.py`)의 순수 함수만 있다. `ai/` 폴더에서 돌린다(네트워크·AI 호출 없음).

```bash
py -m unittest test_release_notes
```

시큐어코딩 점검 규칙(`securecode/rules/*.yml`)을 고쳤으면 규칙 옆 예제 파일로 회귀 테스트를 돌린다. 규칙 파일과 같은 이름의
예제(`sql-injection.java` 등)에 걸려야 할 줄은 `ruleid: <규칙id>`, 걸리면 안 되는 줄은 `ok: <규칙id>` 주석을 바로 윗줄에 단다.
`semgrep --test .`로 한꺼번에 돌리면 Windows에서 `~/.semgrep/settings.yml` 잠금(PermissionError)으로 전체가 죽거나 일부가 조용히 빠진다
(`SEMGREP_SETTINGS_FILE`·`-j 1`로도 안 된다). 그래서 규칙 파일·예제 파일마다 하나씩 순서대로 돌리는 `test_rules.py`를 쓴다
(semgrep이 PATH에 없으면 파이썬 Scripts 폴더에서 찾는다). 결과 끝의 "N/N 규칙 파일 통과"를 본다.

```bash
cd ../securecode
py test_rules.py
```

- 테스트 주석(`ruleid:`·`ok:`)은 **`//`·`<!-- -->`·`#` 한 줄 주석**으로 단다. 블록 주석 안의 ` * ruleid:`나 JSX의 `{/* ruleid: */}`는
  semgrep --test가 인식하지 못해 "incorrect lines"로 실패한다(탐지는 정상인데 테스트만 깨진다).
- taint 규칙의 출처에는 `HttpServletRequest` 값과 Spring 요청 파라미터(`@RequestParam`·`@PathVariable`·`@RequestHeader`·`@RequestBody`)를 함께 둔다.
  사내 시스템은 `@RequestBody Map`으로 받아 `param.get("x")`로 꺼내는 경우가 대부분이라, request만 보면 거의 걸리지 않는다.
  한 파일 안 여러 규칙은 YAML 앵커(`pattern-sources: &request-sources` / `*request-sources`)로 같은 출처를 쓴다(`injection.yml`).

Semgrep은 `securecode/requirements.txt`로 버전을 고정한다. 올릴 때는 그 파일을 바꾸고, 규칙 테스트와 실제 앱 점검 건수가 그대로인지 확인한다
(엔진 버전이 바뀌면 같은 규칙이라도 탐지가 달라질 수 있다 — 점검 이력에 엔진 버전이 남는다).

```bash
py -m pip install -r ../securecode/requirements.txt
```

- 규칙 하나에 언어가 다른 규칙(java + generic)을 섞지 않는다 — `--test`가 같은 이름의 예제를 그 파일의 모든 언어로 파싱해서
  구문 오류가 난다(그래서 `hardcoded-secret.yml`과 `hardcoded-secret-config.yml`을 나눴다).
- `metavariable-regex`는 값의 **처음부터** 맞춘다(re.match). 중간 문자열을 찾으려면 `.*`로 시작한다.
- 규칙 id에 점(.)을 넣지 않는다 — 결과의 `check_id`에서 마지막 점 뒤를 규칙 id로 쓴다(SemgrepReportParser).
- MyBatis `${}` 연계 추적(`MybatisDollarTracer`)에 **특정 시스템의 어노테이션·키·클래스 이름을 넣지 않는다.** 시스템마다 다른 장치(세션 값을 요청 맵에
  덮어쓰는 AOP, 로그인 정보 객체 이름)는 `securecode/trace-rules.yml`에 항목으로 추가한다. 새 시스템을 점검 대상에 넣으면 그 시스템이 로그인 정보를
  요청 값에 어떻게 넣는지 확인하고 항목을 추가한다 — 없으면 그 값이 클라이언트 값으로 판정된다(위험한 쪽이라 놓치지는 않지만 오탐이 된다).
  이 파일은 `rules/` 밖에 둔다(안에 두면 Semgrep이 규칙으로 읽는다).
- 비밀값 규칙의 id는 `hardcoded-secret`을 포함해야 코드 조각·지문에서 값이 가려진다(SecureCodeSnippetBuilder.isSecretRule).

---

## 2. 개발 원칙 — 주먹구구식으로 개발하지 않는다

이 저장소의 기존 코드는 이미 이 원칙대로 쓰여 있다. 새로 짜는 코드도 같은 수준을 지킨다.

### 2.1 먼저 읽고, 그 다음에 쓴다

무언가를 만들기 전에 **이미 있는지부터 확인한다.** 비슷한 것을 새로 만드는 순간 이 프로젝트는
"화면마다 제각각"으로 돌아간다. 이 코드베이스는 그 상태에서 한 번 빠져나온 이력이 있고
(그리드 렌더링, 공통 CSS, select 옵션 하드코딩), 다시 되돌리지 않는다.

- 그리드가 필요하면 → `Grid.renderHeader` / `Grid.render`. `tr`/`td`를 직접 만들지 않는다.
- 그리드 값을 읽을 때는 → `Grid.getRows(tbody)` / `Grid.getRow(tbody, rowIndex)`. `tr._fields.xxx.value`나 `tr.dataset.id`를 직접 읽지 않는다. 신규 행 여부는 `row._isNew`, 삭제 선택은 `row._selected`, 저장 전 신규 행 삭제는 `Grid.removeRows`, "신규" 버튼은 `Grid.addRow(tbody)`(안내 행 제거·맨 위 삽입·첫 입력칸 포커스까지 한다).
- 입력 셀이 필요하면 → 컬럼의 `type`(`text`/`number`/`select`/`checkbox`/`row-select`).
  화면마다 `createInput()` 류 함수를 다시 만들지 않는다.
- select 옵션이 필요하면 → `ComCd.fillSelect(el, 'GROUP')`. 코드값을 HTML에 하드코딩하지 않는다.
- 버튼/패널/색상이 필요하면 → `common-ui.css`의 클래스와 `:root` 변수. 화면 `<style>`에는
  **그 화면에서만 다른 값**만 남긴다. 버튼(`.btn`) 크기·그리드 행 높이는 모든 화면 공통이라 화면에서 덮어쓰지 않는다.
- fetch 호출에 CSRF 헤더나 스피너를 직접 붙이지 않는다 — `loading-overlay` 래퍼가 이미 한다.
- 새 화면의 첫 줄은 `<section th:replace="~{fragments/page-toolbar :: toolbar}"></section>` 한 줄이다. 공통 버튼(조회/신규/저장/삭제/초기화/기타1~5)은 **마크업에 쓰지 않는다** — 프로그램 관리·사용자별 권한관리 설정대로 서버가 그린다. 화면 JS는 `PageButtons.bind({ btnSearch: ..., btnAdd: ..., btnEtc1: ... })`로만 핸들러를 건다(`getElementById(...).addEventListener`로 걸면 권한 없는 사용자에게서 null 오류로 스크립트가 멈춘다). 단축키(F3/F4/F5/F9/F12)와 `[F3]` 표기는 자동이다.
- 그리드 복사·엑셀 다운로드는 화면에 만들지 않는다 — `grid.js` 우클릭 메뉴가 모든 그리드에 이미 붙어 있다. 엑셀 파일이 따로 필요하면 `XlsxWriter.download`를 쓰고 CSV를 새로 만들지 않는다.
- 그리드 `<tbody>`는 비워 둔다. 첫 안내 행은 `Grid.renderHeader`가 넣고, 문구가 다르면 `{ initialMessage }`로 준다.
- 조회영역은 마크업으로 쓰지 않고 `SearchForm.render`(`/js/search-form.js`)에 필드 정의로 넘긴다 — 그리드의 `COLUMNS`와 같은 방식. 조회조건을 화면에서 거를 때는 필드 id를 행 데이터 키와 맞추고 `list.filter(search.matches)`를 쓴다. `contains` 류 함수를 화면에 다시 만들지 않는다.
- 버전 비교가 필요하면 → `NvdVersionRangeChecker` / `OsvVersionRangeChecker` / `VersionLineSelector`.
  문자열 비교를 새로 짜지 않는다(`.RELEASE`, `.Final` 같은 접미사에서 반드시 틀린다).

공통 자산의 전체 목록과 각 파일의 역할은 [`llm-analysis.md` 5장](llm-analysis.md)에 있다.

### 2.2 중복은 세 번째가 아니라 두 번째에 없앤다

같은 코드를 두 번째로 쓰게 되는 순간이 공통화할 시점이다. 다만 **공통화의 방향은 "위로 올리기"다.**

- 화면 2개가 같은 동작을 하면 → 화면에 복사하지 말고 `grid.js` / `common-ui.css`로 올린다.
- 관리 화면 API에 권한이 필요하면 → `@PreAuthorize` 문자열을 늘리지 말고 컨트롤러(클래스 또는
  메서드)에 `@RequiresProgram("app-mng")`를 붙인다. `SecurityConfig`는 고치지 않는다.
- 프롬프트 규칙이 두 프롬프트에 겹치면 → `ai/prompts/rules/*.md`로 빼고 `{{include: rules/xxx.md}}`로 부른다.

반대로, **아직 한 번뿐인 것을 미리 추상화하지도 않는다.** 쓰이지 않을 확장 포인트, 구현체가
하나뿐인 인터페이스, "나중을 위한" 옵션 파라미터는 중복만큼이나 유지보수 비용이다.

### 2.3 리팩토링을 전제로 짠다

기능을 "돌아가게" 만드는 것과 "다음 사람이 고칠 수 있게" 만드는 것은 같은 작업의 앞뒤다.
새 기능을 붙이면서 그 자리에 드러난 구조 문제는 그때 정리한다 — 뒤로 미룬 정리는 하지 않게 된다.

- **작업 전에 한 번 생각한다**: 이 변경이 어느 레이어의 책임인가? 지금 파일이 맞는 자리인가?
  컨트롤러에 비즈니스 로직을 넣고 있다면 그건 서비스로 갈 코드다.
- **한 덩어리가 커지면 이름 있는 조각으로 쪼갠다.** `ScanOrchestrationService`가 오케스트레이션만
  하고 실제 일은 `git`/`maven`/`osv`/`vulnerability` 서비스가 하는 것이 그 예다.
- **판단 로직은 순수 클래스로 분리한다.** `NvdVersionRangeChecker`, `OsvFixVersionResolver`,
  `VersionLineSelector`가 그렇다 — Spring 컨텍스트 없이 단위 테스트가 되기 때문에 테스트가 있다.
- **이름을 정확히 쓴다.** 패키지명과 실제 역할이 어긋나면(과거 `dto.git`에 스캔 DTO가 있던 사례)
  그때그때 고친다. 이름이 맞지 않는 폴더는 곧 중복이 생기는 자리다.
- **외부 HTTP 호출을 `@Transactional` 안에 두지 않는다.** 조회·외부 검증을 먼저 끝내고, 쓰기만
  트랜잭션 안에서 한다. `VulnerabilityService.syncCveById` / `applyAiAssessment`가 일부러
  `@Transactional`을 안 붙인 이유다(NVD·Maven Central·OSV를 부르는 동안 DB 커넥션이 묶인다).
  순수 DB 작업(`resolveMissingVulnerabilities`)에는 그대로 붙인다.
- 구조를 바꿨으면 **관련 주석과 문서까지 같이 고친다.** 설명이 틀린 주석은 없느니만 못하다.

### 2.4 주석은 "무엇"이 아니라 "왜"를 적는다

이 저장소의 주석은 대부분 **그 선택을 한 이유와, 다르게 했을 때 실제로 터졌던 문제**를 적고 있다.
이 스타일을 그대로 따른다. 코드를 읽으면 알 수 있는 내용은 적지 않는다.

- 좋은 예: `Vulnerability`의 복합 유니크 주석(왜 `group_id`/`artifact_id`가 키에 들어가야 하는지,
  뺐을 때 어떤 버그가 났는지), `application.properties`의 H2 콘솔 주석(왜 꺼두는지),
  `AiAssessmentTriggerService`의 `-u` 주석(왜 무버퍼로 띄우는지).
- 나쁜 예: `// 사용자를 조회한다` 위의 `findUser()`.

주석과 로그, 커밋 메시지는 모두 **한국어**로 쓴다.

### 2.5 실패하는 방향을 정해 둔다

- **인증은 fail closed** — `PUBLIC_URLS`에 없으면 전부 로그인을 요구한다
  (`anyRequest().access(requiresProgramAuthorizationManager)`).
- **권한(프로그램 단위)은 그렇지 않다** — `@RequiresProgram`을 안 붙인 API는 "로그인만 하면 되는
  API"로 열린다. 구조가 막아주지 않으므로 **관리 화면 API를 만들 때 어노테이션 부착은 사람이
  챙겨야 한다**(4장 체크리스트).
- **외부 호출 한 건의 실패가 전체를 죽이지 않는다** — 스캔의 CVE별 NVD 조회는 건별로 try/catch해서
  그 건만 건너뛴다. 대신 **건너뛴 사실을 반드시 위로 올린다**(`ScanResult.failedCveCount` → 화면 알림).
  조용히 넘어가면 "취약점이 없는 것"과 "조회를 못 한 것"을 구분할 수 없게 되는데, 이 프로젝트에서
  그건 가장 나쁜 실패다.
- **반복되는 외부 API 호출에는 간격·재시도·타임아웃을 반드시 건다** — CVE 건수만큼 도는 호출은
  한도 초과(429)를 맞는 게 정상이다(`NvdClient`).

### 2.6 되돌릴 수 없는 일은 확인부터

DB 스키마 변경, 대량 삭제, 외부로 나가는 호출(Git push, 외부 API 대량 호출)은 실행 전에 범위를
명확히 하고 확인을 받는다. 스캔은 실제로 외부 저장소를 clone하고 Maven을 돌리므로 가볍게 반복
실행하지 않는다.

---

## 3. 보안 관련 불변 규칙

아래는 각각 실제 취약점을 막기 위해 들어간 것들이다. **편의를 위해 되돌리지 않는다.**
현재 어떻게 동작하는지는 [`llm-analysis.md` 6장](llm-analysis.md)을 본다.

| 규칙 | 이유 |
| --- | --- |
| `anyRequest().access(requiresProgramAuthorizationManager)` 유지 | `PUBLIC_URLS` 외에는 전부 로그인을 요구하기 위함. 여기에 URL 패턴을 다시 나열하지 않는다 |
| 관리 화면 API에는 `@RequiresProgram` 부착 | **안 붙이면 로그인한 전원에게 열린다.** 구조가 막아주지 않는 유일한 지점 |
| `@PreAuthorize`는 `@RequiresProgram`으로 표현 불가능할 때만 | 현재 예외는 `ComCdController.getCodes`의 `includeInactive` 단 하나 — 요청 내용(쿼리 파라미터)에 따라 필요한 권한이 달라지는 경우 |
| `/api/**` CSRF 검증 유지 (`/api/ai/**` 제외) | 제외하면 로그인한 관리자가 악성 페이지만 열어도 `POST /api/scan` 등이 대신 날아간다 |
| `/api/ai/**`만 CSRF에서 제외 | 세션 쿠키가 아니라 헤더 토큰으로만 인증하는 배치 전용 경로라 CSRF의 전제(브라우저가 쿠키를 자동 전송)가 성립하지 않는다. **빼지 않으면 배치의 POST가 전부 403이 되는데, GET은 통과해서 "판단은 다 하고 저장만 실패"로 조용히 깨진다** |
| `spring.h2.console.enabled=false` 유지 | H2 콘솔은 `CREATE ALIAS`로 사실상 원격 코드 실행이 가능하다 |
| 스캔은 앱 관리에 등록된 `repoUrl/branch`만 허용 | 임의 URL 스캔 시 GitLab PAT 유출, 악성 pom.xml 실행, SSRF 위험 |
| 앱 등록 시 `RepoUrlValidator`로 호스트·스킴 검증 | 위 규칙은 "등록된 것만"이지 "등록되는 것"은 안 거른다. 등록 자리에서 막지 않으면 그 뒤로 거를 자리가 없다 |
| `/api/ai/**`는 `X-Internal-Token` 헤더로 자체 인증 | 세션 없는 파이썬 배치 전용 경로 |
| 초기 관리자 비밀번호는 기동 시 무작위 생성 후 로그로만 노출 | 소스에 평문 비밀번호를 두지 않기 위함 |
| 화면(`/program/{*path}`)도 Program 권한을 검사 | API만 막으면 "메뉴엔 없는데 주소로는 열린다"가 되어 접근 제어 기준이 화면과 API에서 갈린다 |
| AI로 저장소 원문을 보낼 때는 `SecretMasker`로 가린다 | 지금은 fix-plan의 pom.xml 하나. 비밀번호·토큰·계정 든 URL이 Claude API로 나가고, 돌아온 pom이 DB·화면에 다시 저장된다. **새로 원문을 AI 입력에 넣으면 같은 방식으로 가리고 되돌린다.** 소스 코드는 AI로 보내지 않는다(사내 정책) |
| 역할(`role`)은 공통코드 `ROLE` 그룹 값만 허용 | 임의 문자열이 저장되면 `User.roles(...)`에서 터져 **그 계정의 로그인만 나중에 깨진다** |

### 시크릿

`application*.properties`는 `.gitignore`에 올라가 있다. **커밋하지 않는다.**
새 설정값을 추가할 때는 문서에 "키 이름과 용도"만 적고 값은 적지 않는다.

---

## 4. 작업 체크리스트

변경을 끝내기 전에 확인한다.

- [ ] 이미 있는 공통 모듈(`grid.js`, `common-ui.css`, `ComCd`, `*RangeChecker`)을 썼는가?
- [ ] 같은 코드를 두 군데 이상에 복사하지 않았는가?
- [ ] 관리 화면 API를 만들었다면 `@RequiresProgram`을 붙였는가? (빠뜨리면 그대로 열린다)
- [ ] 판단 로직을 넣었다면 Spring 없이 테스트 가능한 순수 클래스로 분리하고 테스트를 붙였는가?
- [ ] 비자명한 선택에 "왜"를 설명하는 한국어 주석을 남겼는가?
- [ ] 구조를 바꿨다면 관련 주석 / `backend/README.md` / `docs/llm-analysis.md`를 같이 고쳤는가?
- [ ] `./mvnw test`가 통과하는가? (`ai/release_notes.py`를 고쳤으면 `py -m unittest test_release_notes`도, 코드 점검 규칙을 고쳤으면 `py test_rules.py`(securecode 폴더)도)
