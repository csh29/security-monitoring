package com.sjinc.securitymonitor.config;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.ComCd;
import com.sjinc.securitymonitor.domain.ComCdGroup;
import com.sjinc.securitymonitor.domain.Program;
import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.domain.User;
import com.sjinc.securitymonitor.domain.UserProgramPermission;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.ComCdGroupRepository;
import com.sjinc.securitymonitor.repository.ComCdRepository;
import com.sjinc.securitymonitor.repository.ProgramRepository;
import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import com.sjinc.securitymonitor.repository.UserRepository;
import com.sjinc.securitymonitor.service.ai.AiAssessmentTriggerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * DB가 비어 있을 때(사용자 0명) 한 번만 관리자·프로그램·권한·공통코드·샘플 앱을 심는다. 파일 DB라 기존 DB에는
 * 새로 추가한 데이터가 들어가지 않으므로 필요하면 "없으면 넣기"로 따로 심는다. 비밀번호는 소스에 두지 않고
 * 최초 생성 때 무작위로 만들어 로그로만 알린다.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private static final String INITIAL_PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private static final int INITIAL_PASSWORD_LENGTH = 20;
    private static final String SECURE_CODE_STATUS_GROUP = "SC_STATUS";
    private static final String SECURE_CODE_SEVERITY_GROUP = "SC_SEVERITY";
    private static final String APP_SOURCE_GROUP = "APP_SOURCE";
    private static final String MENU_GROUP = "MENU_GROUP";

    private final UserRepository userRepository;
    private final ProgramRepository programRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;
    private final AppRepository appRepository;
    private final ComCdGroupRepository comCdGroupRepository;
    private final ComCdRepository comCdRepository;
    private final PasswordEncoder passwordEncoder;

    /** AI 배치 자동 실행 스위치(공통코드 AI_CONFIG/AUTO_TRIGGER)의 초기값. 실행 중 켜고 끄기는 공통코드 관리 화면에서 한다. */
    @Value("${ai.auto-trigger.enabled:true}")
    private boolean aiAutoTriggerDefault;

    @Override
    public void run(String... args) {
        // 아래 "DB가 비었을 때 한 번만" 규칙보다 먼저 돈다 — 기능이 생기기 전에 만들어진 DB에도 들어가야 화면 select가 채워진다.
        seedSecureCodeStatusIfAbsent();
        seedSecureCodeSeverityIfAbsent();
        seedAppSourceIfAbsent();
        seedMenuGroupIfAbsent();

        if (userRepository.count() == 0) seedInitialData();
        // 관리자를 만든 뒤에 돈다 — 새 DB에서도 관리자가 기능 화면 권한을 받게.
        seedFeatureProgramsIfAbsent();
    }

    /** DB가 비었을 때 한 번만 — 초기 관리자, 관리 프로그램, 공통코드, 예시 앱. */
    private void seedInitialData() {

        String initialPassword = generateInitialPassword();
        User admin = userRepository.save(User.builder()
                .username("admin")
                .userNm("관리자")
                .password(passwordEncoder.encode(initialPassword))
                .role("ADMIN")
                .build());
        log.warn("초기 관리자 계정을 생성했습니다. username=admin, password={} "
                + "(이 로그에만 한 번 출력됩니다 — 로그인 후 반드시 비밀번호를 변경하세요)", initialPassword);

        // 관리 그룹 프로그램(메뉴 그룹이 비어 있으면 관리).
        Program programMng = programRepository.save(Program.builder()
                .programId("program-mng")
                .programNm("프로그램 관리")
                .url("/program/program-mng")
                .sortOrder(1)
                .useYn("Y")
                .searchYn("Y")
                .newYn("Y")
                .saveYn("Y")
                .deleteYn("Y")
                .resetYn("Y")
                .build());

        Program userMng = programRepository.save(Program.builder()
                .programId("user-mng")
                .programNm("사용자 관리")
                .url("/program/user-mng")
                .sortOrder(2)
                .useYn("Y")
                .searchYn("Y")
                .newYn("Y")
                .saveYn("Y")
                .deleteYn("Y")
                .resetYn("Y")
                .build());

        Program userPermissionMng = programRepository.save(Program.builder()
                .programId("user-permission-mng")
                .programNm("사용자별 권한관리")
                .url("/program/user-permission-mng")
                .sortOrder(3)
                .useYn("Y")
                .searchYn("Y")
                .newYn("N")
                .saveYn("Y")
                .deleteYn("N")
                .resetYn("Y")
                .build());

        Program appMng = programRepository.save(Program.builder()
                .programId("app-mng")
                .programNm("앱 관리")
                .url("/program/app-mng")
                .sortOrder(4)
                .useYn("Y")
                .searchYn("Y")
                .newYn("Y")
                .saveYn("Y")
                .deleteYn("Y")
                .resetYn("Y")
                .build());

        Program comCdMasterMng = programRepository.save(Program.builder()
                .programId("com-cd-master-mng")
                .programNm("공통코드마스터 관리")
                .url("/program/com-cd-master-mng")
                .sortOrder(5)
                .useYn("Y")
                .searchYn("Y")
                .newYn("Y")
                .saveYn("Y")
                .deleteYn("Y")
                .resetYn("Y")
                .build());

        Program comCdMng = programRepository.save(Program.builder()
                .programId("com-cd-mng")
                .programNm("공통코드 관리")
                .url("/program/com-cd-mng")
                .sortOrder(6)
                .useYn("Y")
                .searchYn("Y")
                .newYn("Y")
                .saveYn("Y")
                .deleteYn("Y")
                .resetYn("Y")
                .build());

        // 초기 관리자는 모든 프로그램의 모든 공통 버튼을 쓸 수 있다(프로그램이 쓰지 않는 버튼은 어차피 안 보인다).
        for (Program program : List.of(programMng, userMng, userPermissionMng, appMng,
                comCdMasterMng, comCdMng)) {
            userProgramPermissionRepository.save(allButtonsPermission(admin, program));
        }





        // 화면마다 하드코딩되던 select 옵션(역할/심각도/처리상태)을 공통코드로 관리한다. 마스터(그룹)를
        // 먼저 만들고, 값(codeValue)은 기존 화면 로직/뱃지 클래스가 그대로 참조하던 문자열과 동일하게 디테일을 심는다.
        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup("ROLE").groupName("역할").sortOrder(1).useYn("Y").build());
        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup("SEVERITY").groupName("심각도").sortOrder(2).useYn("Y").build());
        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup("VULN_STATUS").groupName("처리여부").sortOrder(3).useYn("Y").build());
        // select 옵션이 아니라 실행 중에 바꾸는 설정 스위치. 사용여부(Y/N)가 곧 켜짐/꺼짐이다(ComCdService.isEnabled).
        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup(AiAssessmentTriggerService.CONFIG_GROUP).groupName("AI 배치 설정").sortOrder(4).useYn("Y")
                .remark("사용여부 = 켜짐/꺼짐. 바꾸면 재기동 없이 다음 스캔부터 적용").build());

        int sort = 1;
        comCdRepository.save(ComCd.builder()
                .codeGroup("ROLE").codeValue("ADMIN").codeName("ADMIN").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder()
                .codeGroup("ROLE").codeValue("USER").codeName("USER").sortOrder(sort).useYn("Y").build());

        sort = 1;
        comCdRepository.save(ComCd.builder()
                .codeGroup("SEVERITY").codeValue("CRITICAL").codeName("CRITICAL").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder()
                .codeGroup("SEVERITY").codeValue("HIGH").codeName("HIGH").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder()
                .codeGroup("SEVERITY").codeValue("MEDIUM").codeName("MEDIUM").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder()
                .codeGroup("SEVERITY").codeValue("LOW").codeName("LOW").sortOrder(sort).useYn("Y").build());

        sort = 1;
        comCdRepository.save(ComCd.builder()
                .codeGroup("VULN_STATUS").codeValue("OPEN").codeName("미해결").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder()
                .codeGroup("VULN_STATUS").codeValue("RESOLVED").codeName("처리완료").sortOrder(sort).useYn("Y").build());

        comCdRepository.save(ComCd.builder()
                .codeGroup(AiAssessmentTriggerService.CONFIG_GROUP).codeValue(AiAssessmentTriggerService.AUTO_TRIGGER_CODE)
                .codeName("스캔 후 AI 배치 자동 실행").sortOrder(1).useYn(aiAutoTriggerDefault ? "Y" : "N")
                .remark("사용 체크 = 켜짐. 켜 두면 스캔 뒤 Claude API를 호출한다(과금)").build());

        appRepository.save(App.builder()
                .repoUrl("https://git.sejung.co.kr/crm/back.git")
                .branch("dev")
                .systemName("CRM_BACK")
                .description("CRM 백엔드")
                .build());

        appRepository.save(App.builder()
                .repoUrl("https://git.sejung.co.kr/crm/batch.git")
                .branch("dev")
                .systemName("CRM_BATCH")
                .description("CRM 배치")
                .build());
    }

    /**
     * 코드 점검 처리여부(공통코드 SC_STATUS). 그룹이 없을 때만 심는다 — 이미 있으면 공통코드 관리 화면에서 사람이 고친 이름·순서를
     * 덮어쓰지 않는다. 값은 SecureCodeFinding의 상태 상수와 같아야 한다(뱃지 클래스도 이 값을 소문자로 쓴다).
     */
    private void seedSecureCodeStatusIfAbsent() {
        if (comCdGroupRepository.existsById(SECURE_CODE_STATUS_GROUP)) return;

        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup(SECURE_CODE_STATUS_GROUP).groupName("코드 점검 처리여부").sortOrder(5).useYn("Y").build());
        int sort = 1;
        comCdRepository.save(ComCd.builder().codeGroup(SECURE_CODE_STATUS_GROUP)
                .codeValue(SecureCodeFinding.OPEN).codeName("미조치").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(SECURE_CODE_STATUS_GROUP)
                .codeValue(SecureCodeFinding.RESOLVED).codeName("조치완료").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(SECURE_CODE_STATUS_GROUP)
                .codeValue(SecureCodeFinding.FALSE_POSITIVE).codeName("오탐").sortOrder(sort++).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(SECURE_CODE_STATUS_GROUP)
                .codeValue(SecureCodeFinding.ACCEPTED).codeName("위험수용").sortOrder(sort).useYn("Y")
                .remark("실제 약점이지만 다른 통제가 있거나 영향이 작아 고치지 않기로 한 건").build());
        log.info("공통코드 {}(코드 점검 처리여부)를 추가했습니다.", SECURE_CODE_STATUS_GROUP);
    }

    /**
     * 코드 점검 심각도(공통코드 SC_SEVERITY) — HIGH/MEDIUM/LOW. 라이브러리 취약점의 SEVERITY에는 CVSS의 CRITICAL이 있지만 코드 점검 등급은
     * Semgrep ERROR/WARNING/INFO와 연계 추적 판정에서 나와 CRITICAL이 없다. 같은 그룹을 쓰면 코드 점검 결과 조회조건에 걸리는 행이 없는 CRITICAL이
     * 보여서 따로 둔다. 값은 SEVERITY와 같은 문자열이라 뱃지·정렬(SeverityOrder)은 그대로 쓴다. SC_STATUS와 같은 이유로 그룹이 없을 때만 심는다.
     */
    private void seedSecureCodeSeverityIfAbsent() {
        if (comCdGroupRepository.existsById(SECURE_CODE_SEVERITY_GROUP)) return;

        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup(SECURE_CODE_SEVERITY_GROUP).groupName("코드 점검 심각도").sortOrder(6).useYn("Y").build());
        int sort = 1;
        for (String level : new String[]{"HIGH", "MEDIUM", "LOW"}) {
            comCdRepository.save(ComCd.builder().codeGroup(SECURE_CODE_SEVERITY_GROUP)
                    .codeValue(level).codeName(level).sortOrder(sort++).useYn("Y").build());
        }
        log.info("공통코드 {}(코드 점검 심각도)를 추가했습니다.", SECURE_CODE_SEVERITY_GROUP);
    }

    /**
     * 앱 소스 출처(공통코드 APP_SOURCE) — 앱 관리 화면의 select. 값은 App.SOURCE_GIT/SOURCE_UPLOAD와 같아야 한다.
     * 업로드 앱은 zip을 올려 코드 점검만 한다(라이브러리 스캔 불가). SC_STATUS와 같은 이유로 그룹이 없을 때만 심는다.
     */
    private void seedAppSourceIfAbsent() {
        if (comCdGroupRepository.existsById(APP_SOURCE_GROUP)) return;

        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup(APP_SOURCE_GROUP).groupName("앱 소스 출처").sortOrder(7).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(APP_SOURCE_GROUP)
                .codeValue(App.SOURCE_GIT).codeName("Git").sortOrder(1).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(APP_SOURCE_GROUP)
                .codeValue(App.SOURCE_UPLOAD).codeName("소스 업로드").sortOrder(2).useYn("Y")
                .remark("Git으로 접근할 수 없는 앱 — zip을 올려 코드 점검만 한다(라이브러리 스캔 불가)").build());
        log.info("공통코드 {}(앱 소스 출처)를 추가했습니다.", APP_SOURCE_GROUP);
    }

    /** 사이드바 메뉴 그룹(공통코드 MENU_GROUP) — 프로그램 관리 화면의 select. 값은 Program.GROUP_*와 같아야 한다. */
    private void seedMenuGroupIfAbsent() {
        if (comCdGroupRepository.existsById(MENU_GROUP)) return;

        comCdGroupRepository.save(ComCdGroup.builder()
                .codeGroup(MENU_GROUP).groupName("메뉴 그룹").sortOrder(8).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(MENU_GROUP)
                .codeValue(Program.GROUP_LIB).codeName("라이브러리 취약점").sortOrder(1).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(MENU_GROUP)
                .codeValue(Program.GROUP_SECURE).codeName("시큐어코딩").sortOrder(2).useYn("Y").build());
        comCdRepository.save(ComCd.builder().codeGroup(MENU_GROUP)
                .codeValue(Program.GROUP_MNG).codeName("관리").sortOrder(3).useYn("Y").build());
        log.info("공통코드 {}(메뉴 그룹)를 추가했습니다.", MENU_GROUP);
    }

    /**
     * 기능 화면(라이브러리 취약점 4종·시큐어코딩 2종)을 프로그램으로 등록한다. 없을 때만 넣어 사람이 고친 이름·순서를 덮어쓰지 않는다.
     * 예전엔 로그인만으로 열리던 화면이라, 새로 넣을 때 기존 사용자 모두에게 전체 버튼 권한을 줘 접근을 잃지 않게 한다.
     */
    private void seedFeatureProgramsIfAbsent() {
        List<Program> added = new ArrayList<>();
        addIfAbsent(added, "vulnerability-mng", "취약점 점검 결과", Program.GROUP_LIB, "⚠", 1, "Y", "N", "Y", "N", "N");
        addIfAbsent(added, "vulnerability-search", "취약점 점검", Program.GROUP_LIB, "⌕", 2, "Y", "N", "N", "N", "Y");
        addIfAbsent(added, "fix-plan", "조치안", Program.GROUP_LIB, "🛠", 3, "Y", "N", "N", "N", "Y");
        addIfAbsent(added, "report", "리포트", Program.GROUP_LIB, "📄", 4, "N", "N", "N", "N", "N");
        addIfAbsent(added, "secure-code-scan", "코드 점검", Program.GROUP_SECURE, "⛨", 1, "Y", "N", "N", "N", "Y");
        addIfAbsent(added, "secure-code-mng", "코드 점검 결과", Program.GROUP_SECURE, "☑", 2, "Y", "N", "Y", "N", "N");
        if (added.isEmpty()) return;
        List<User> users = userRepository.findAll();
        for (User user : users) {
            for (Program program : added) userProgramPermissionRepository.save(allButtonsPermission(user, program));
        }
        log.info("기능 화면 프로그램 {}개를 등록하고 사용자 {}명에게 권한을 줬습니다: {}", added.size(), users.size(),
                added.stream().map(Program::getProgramId).toList());
    }

    private void addIfAbsent(List<Program> added, String id, String name, String group, String icon, int sort,
                             String search, String newYn, String save, String delete, String reset) {
        if (programRepository.existsById(id)) return;
        added.add(programRepository.save(Program.builder()
                .programId(id).programNm(name).url("/program/" + id).sortOrder(sort).useYn("Y")
                .menuGroup(group).icon(icon)
                .searchYn(search).newYn(newYn).saveYn(save).deleteYn(delete).resetYn(reset)
                .build()));
    }

    /** 혼동되기 쉬운 문자(0/O, 1/l/I 등)를 뺀 문자셋에서 무작위로 뽑은 초기 비밀번호. */
    private String generateInitialPassword() {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(INITIAL_PASSWORD_LENGTH);
        for (int i = 0; i < INITIAL_PASSWORD_LENGTH; i++) {
            password.append(INITIAL_PASSWORD_CHARS.charAt(random.nextInt(INITIAL_PASSWORD_CHARS.length())));
        }
        return password.toString();
    }

    private static UserProgramPermission allButtonsPermission(User user, Program program) {
        return UserProgramPermission.builder()
                .user(user)
                .program(program)
                .searchYn("Y").newYn("Y").saveYn("Y").deleteYn("Y").resetYn("Y")
                .etc1Yn("Y").etc2Yn("Y").etc3Yn("Y").etc4Yn("Y").etc5Yn("Y")
                .build();
    }
}
