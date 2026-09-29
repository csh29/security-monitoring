package com.sjinc.cvemonitor.config;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.domain.ComCd;
import com.sjinc.cvemonitor.domain.ComCdGroup;
import com.sjinc.cvemonitor.domain.CveSummary;
import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.domain.User;
import com.sjinc.cvemonitor.domain.UserProgramPermission;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.ComCdGroupRepository;
import com.sjinc.cvemonitor.repository.ComCdRepository;
import com.sjinc.cvemonitor.repository.CveSummaryRepository;
import com.sjinc.cvemonitor.repository.ProgramRepository;
import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import com.sjinc.cvemonitor.repository.UserRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;

/**
 * H2가 in-memory라 재기동 시마다 초기화되므로, 로그인용 초기 관리자 계정을 매번 심어둔다.
 *
 * <p>비밀번호는 소스에 평문으로 박아두지 않는다 — 그 상태로 배포되면 계정이 공개된 것과 같다.
 * 대신 기동할 때마다 무작위로 생성해서 로그 한 줄로만 알려준다(운영자는 서버 로그에서 최초 1회
 * 확인하고, 첫 로그인 후 반드시 비밀번호를 바꿔야 한다).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private static final String INITIAL_PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private static final int INITIAL_PASSWORD_LENGTH = 20;

    private final UserRepository userRepository;
    private final ProgramRepository programRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;
    private final AppRepository appRepository;
    private final ComCdGroupRepository comCdGroupRepository;
    private final ComCdRepository comCdRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final CveSummaryRepository cveSummaryRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (userRepository.count() > 0) return;

        String initialPassword = generateInitialPassword();
        User admin = userRepository.save(User.builder()
                .username("admin")
                .userNm("관리자")
                .password(passwordEncoder.encode(initialPassword))
                .role("ADMIN")
                .build());
        log.warn("초기 관리자 계정을 생성했습니다. username=admin, password={} "
                + "(이 로그에만 한 번 출력됩니다 — 로그인 후 반드시 비밀번호를 변경하세요)", initialPassword);

        // 사이드바 고정 메뉴 외에 권한 기반으로 노출되는 추가 프로그램 예시.
        // 실제 프로그램/URL로 교체하거나 관리 화면이 생기면 이 시드는 제거한다.
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

        App crmBack = appRepository.save(App.builder()
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

        seedSampleVulnerabilities(crmBack);
    }

    /**
     * 스캔을 돌리지 않아도 취약점 화면을 확인할 수 있도록 샘플 취약점 2건을 심는다.
     *
     * <p>판단 결과(applyAiAssessment)를 미리 채워 둔다 — 비워 두면 HIGH/CRITICAL 건이 AI 판단 대기
     * (findPendingAssessments)에 잡혀, 다음 스캔 때 파이썬 배치가 샘플 데이터로 Claude API를 호출(과금)한다.
     * ScanSnapshot이 없으므로 fix-plan 대기에도 잡히지 않는다. 설명 요약(CveSummary)도 같은 이유로 미리 심는다
     * — 없으면 설명 요약 대기에 잡혀 샘플 때문에 배치가 뜬다.
     */
    private void seedSampleVulnerabilities(App app) {
        Vulnerability spring4Shell = Vulnerability.builder()
                .app(app)
                .cveId("CVE-2022-22965")
                .groupId("org.springframework")
                .artifactId("spring-beans")
                .version("5.3.17")
                .broughtInBy("org.springframework.boot:spring-boot-starter-web")
                .knownFixedVersions("5.2.20.RELEASE,5.3.18")
                .nvdRangeVulnerable(true)
                .nvdMatchedRange(">= 5.3.0, < 5.3.18")
                .description("[샘플] Spring4Shell — JDK 9+ 환경의 Spring MVC/WebFlux에서 데이터 바인딩을 통한 원격 코드 실행 취약점.")
                .cvssBaseScore(9.8)
                .cvssBaseSeverity("CRITICAL")
                .severity("CRITICAL")
                .publishedDate("2022-04-01")
                .nvdPublished(LocalDateTime.of(2022, 4, 1, 0, 0))
                .build();
        spring4Shell.applyAiAssessment(true, "5.3.18",
                "[샘플] 구조화 범위 판정 결과 설치 버전이 영향 범위 안입니다. (자동 판정, AI 미사용)", "high");
        vulnerabilityRepository.save(spring4Shell);
        seedSampleSummary(spring4Shell, "[샘플] JDK 9 이상에서 동작하는 Spring MVC/WebFlux 애플리케이션의 데이터 바인딩 과정에서 "
                + "원격 코드 실행이 가능한 취약점이다.");

        Vulnerability springExpressionDos = Vulnerability.builder()
                .app(app)
                .cveId("CVE-2023-20863")
                .groupId("org.springframework")
                .artifactId("spring-expression")
                .version("5.3.26")
                .broughtInBy("org.springframework.boot:spring-boot-starter-web")
                .knownFixedVersions("5.2.24.RELEASE,5.3.27,6.0.8")
                .nvdRangeVulnerable(true)
                .nvdMatchedRange(">= 5.3.0, < 5.3.27")
                .description("[샘플] 특수하게 조작한 SpEL 표현식으로 서비스 거부(DoS)를 일으킬 수 있는 취약점.")
                .cvssBaseScore(6.5)
                .cvssBaseSeverity("MEDIUM")
                .severity("MEDIUM")
                .publishedDate("2023-04-13")
                .nvdPublished(LocalDateTime.of(2023, 4, 13, 0, 0))
                .build();
        springExpressionDos.applyAiAssessment(true, "5.3.27",
                "[샘플] 구조화 범위 판정 결과 설치 버전이 영향 범위 안입니다. (자동 판정, AI 미사용)", "high");
        vulnerabilityRepository.save(springExpressionDos);
        seedSampleSummary(springExpressionDos, "[샘플] 조작된 SpEL 표현식을 입력하면 Spring Expression이 과도한 자원을 써서 "
                + "서비스 거부(DoS)가 발생할 수 있는 취약점이다.");
    }

    private void seedSampleSummary(Vulnerability vulnerability, String summary) {
        cveSummaryRepository.save(CveSummary.builder()
                .cveId(vulnerability.getCveId())
                .summary(summary)
                .descriptionHash(CveSummary.hashOf(vulnerability.getDescription()))
                .summarizedAt(LocalDateTime.now())
                .build());
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
