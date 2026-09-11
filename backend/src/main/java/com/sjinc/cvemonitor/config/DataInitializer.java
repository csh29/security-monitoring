package com.sjinc.cvemonitor.config;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.domain.ScanSnapshot;
import com.sjinc.cvemonitor.domain.User;
import com.sjinc.cvemonitor.domain.UserProgramPermission;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.ProgramRepository;
import com.sjinc.cvemonitor.repository.ScanSnapshotRepository;
import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import com.sjinc.cvemonitor.repository.UserRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** H2가 in-memory라 재기동 시마다 초기화되므로, 로그인 테스트용 기본 관리자 계정을 매번 심어둔다. */
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final ProgramRepository programRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;
    private final AppRepository appRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ScanSnapshotRepository scanSnapshotRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (userRepository.count() > 0) return;

        User admin = userRepository.save(User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin1234!"))
                .role("ADMIN")
                .build());

        // 사이드바 고정 메뉴 외에 권한 기반으로 노출되는 추가 프로그램 예시.
        // 실제 프로그램/URL로 교체하거나 관리 화면이 생기면 이 시드는 제거한다.
        Program programManagement = programRepository.save(Program.builder()
                .programId("program-management")
                .name("프로그램 관리")
                .url("/program/program-management")
                .sortOrder(1)
                .useYn("Y")
                .build());

        Program userManagement = programRepository.save(Program.builder()
                .programId("user-management")
                .name("사용자 관리")
                .url("/program/user-management")
                .sortOrder(2)
                .useYn("Y")
                .build());

        Program userPermissionManagement = programRepository.save(Program.builder()
                .programId("user-permission-management")
                .name("사용자별 권한관리")
                .url("/program/user-permission-management")
                .sortOrder(3)
                .useYn("Y")
                .build());

        Program appManagement = programRepository.save(Program.builder()
                .programId("app-management")
                .name("앱 관리")
                .url("/program/app-management")
                .sortOrder(4)
                .useYn("Y")
                .build());

        userProgramPermissionRepository.save(UserProgramPermission.builder()
                .user(admin)
                .program(programManagement)
                .build());

        userProgramPermissionRepository.save(UserProgramPermission.builder()
                .user(admin)
                .program(userManagement)
                .build());

        userProgramPermissionRepository.save(UserProgramPermission.builder()
                .user(admin)
                .program(userPermissionManagement)
                .build());

        userProgramPermissionRepository.save(UserProgramPermission.builder()
                .user(admin)
                .program(appManagement)
                .build());

        App crmBack = appRepository.save(App.builder()
                .repoUrl("https://git.sejung.co.kr/crm/back.git")
                .branch("dev")
                .systemName("CRM_BACK")
                .description("CRM 백엔드")
                .build());

        // 파이썬 AI 판단 배치(ai/vuln_assessor.py) 동작 확인용 샘플. 보안 취약점은 실제로 동시에 여럿 터지는 경우가
        // 흔하므로, 같은 아티팩트(log4j-core)에 CVE 여러 개 + 서로 다른 아티팩트(jackson-databind)까지 섞어서 심는다.
        // 실제 취약점 동기화가 붙으면 이 시드는 제거한다.
        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2021-44228")
                .groupId("org.apache.logging.log4j")
                .artifactId("log4j-core")
                .version("2.14.1")
                .broughtInBy("com.sjinc:crm-back")
                .description("Apache Log4j2 JNDI 조회 기능이 신뢰할 수 없는 LDAP/JNDI 엔드포인트에 대한 " +
                        "메시지 조회 문자열을 제어할 수 있어 원격 코드 실행으로 이어질 수 있다 (Log4Shell).")
                .severity("CRITICAL")
                .cvssBaseScore(10.0)
                .cvssBaseSeverity("CRITICAL")
                .build());

        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2021-45046")
                .groupId("org.apache.logging.log4j")
                .artifactId("log4j-core")
                .version("2.14.1")
                .broughtInBy("com.sjinc:crm-back")
                .description("Log4j 2.15.0의 CVE-2021-44228 수정이 특정 비기본 설정(Context Map 패턴 등)에서는 " +
                        "불완전해서, 공격자가 Thread Context Map(MDC) 입력값을 제어할 수 있으면 여전히 " +
                        "원격 코드 실행 또는 서비스 거부로 이어질 수 있다.")
                .severity("CRITICAL")
                .cvssBaseScore(9.0)
                .cvssBaseSeverity("CRITICAL")
                .build());

        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2021-45105")
                .groupId("org.apache.logging.log4j")
                .artifactId("log4j-core")
                .version("2.14.1")
                .broughtInBy("com.sjinc:crm-back")
                .description("Log4j 2.17.0 이전 버전은 자기 참조(self-referential) lookup을 포함한 로그 메시지를 " +
                        "처리할 때 제어되지 않은 재귀로 인해 StackOverflowError가 발생, 서비스 거부(DoS)로 이어질 수 있다.")
                .severity("HIGH")
                .cvssBaseScore(7.5)
                .cvssBaseSeverity("HIGH")
                .build());

        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2019-12384")
                .groupId("com.fasterxml.jackson.core")
                .artifactId("jackson-databind")
                .version("2.9.8")
                .broughtInBy("com.sjinc:crm-back")
                .description("FasterXML jackson-databind 2.9.8 이하 버전은 기본 타이핑이 활성화된 상태에서 " +
                        "logback-core 등 클래스패스상의 gadget을 이용한 역직렬화로 원격 코드 실행이 가능하다.")
                .severity("HIGH")
                .cvssBaseScore(8.1)
                .cvssBaseSeverity("HIGH")
                .build());

        // 전이 의존성 시나리오 확인용: logback-classic은 pom.xml에 직접 선언돼 있지 않고
        // logstash-logback-encoder가 끌고 들어온다(broughtInBy가 아티팩트 자신과 다름).
        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2024-12798")
                .groupId("ch.qos.logback")
                .artifactId("logback-classic")
                .version("1.4.14")
                .broughtInBy("net.logstash.logback:logstash-logback-encoder")
                .description("Logback의 JaninoEventEvaluator가 공격자가 작성한 설정을 통해 임의 코드를 " +
                        "실행할 수 있다.")
                .severity("HIGH")
                .cvssBaseScore(7.1)
                .cvssBaseSeverity("HIGH")
                .build());

        // LOW/MEDIUM 등급 샘플 — ai.assessment.severities(HIGH,CRITICAL)에서 제외되고 fix-plan의
        // lowSeverityNote로만 요약되는지 확인하기 위한 시드.
        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2020-9488")
                .groupId("org.apache.logging.log4j")
                .artifactId("log4j-core")
                .version("2.14.1")
                .broughtInBy("com.sjinc:crm-back")
                .description("Log4j 1.2.x부터 2.13.1 이전 SMTPAppender가 SMTP 서버 인증서를 제대로 " +
                        "검증하지 않아, 중간자 공격자가 SMTPS 연결의 로그 이벤트를 가로챌 수 있다.")
                .severity("LOW")
                .cvssBaseScore(3.7)
                .cvssBaseSeverity("LOW")
                .build());

        vulnerabilityRepository.save(Vulnerability.builder()
                .app(crmBack)
                .cveId("CVE-2020-36518")
                .groupId("com.fasterxml.jackson.core")
                .artifactId("jackson-databind")
                .version("2.9.8")
                .broughtInBy("com.sjinc:crm-back")
                .description("jackson-databind는 대규모/깊게 중첩된 JSON 입력을 처리할 때 " +
                        "StackOverflowError가 발생할 수 있어 서비스 거부로 이어질 수 있다.")
                .severity("MEDIUM")
                .cvssBaseScore(5.9)
                .cvssBaseSeverity("MEDIUM")
                .build());

        // fix-plan 배치(stage 2) 동작 확인용 pom.xml/dependency:tree 샘플. 실제 스캔이 남기는 스냅샷을 흉내낸 것.
        ScanSnapshot snapshot = ScanSnapshot.builder().app(crmBack).build();
        snapshot.updateSnapshot(
                """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <parent>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-parent</artifactId>
                        <version>3.2.6</version>
                        <relativePath/>
                    </parent>
                    <groupId>com.sjinc</groupId>
                    <artifactId>crm-back</artifactId>
                    <version>1.0.0</version>
                    <properties>
                        <maven.compiler.source>17</maven.compiler.source>
                        <maven.compiler.target>17</maven.compiler.target>
                    </properties>
                    <dependencies>
                        <dependency>
                            <groupId>org.apache.logging.log4j</groupId>
                            <artifactId>log4j-core</artifactId>
                            <version>2.14.1</version>
                        </dependency>
                        <dependency>
                            <groupId>com.fasterxml.jackson.core</groupId>
                            <artifactId>jackson-databind</artifactId>
                            <version>2.9.8</version>
                        </dependency>
                        <dependency>
                            <groupId>net.logstash.logback</groupId>
                            <artifactId>logstash-logback-encoder</artifactId>
                            <version>7.4</version>
                        </dependency>
                    </dependencies>
                </project>
                """,
                """
                com.sjinc:crm-back:jar:1.0.0
                +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
                +- com.fasterxml.jackson.core:jackson-databind:jar:2.9.8:compile
                +- net.logstash.logback:logstash-logback-encoder:jar:7.4:compile
                |  \\- ch.qos.logback:logback-classic:jar:1.4.14:compile
                |     \\- ch.qos.logback:logback-core:jar:1.4.14:compile
                """
        );
        scanSnapshotRepository.save(snapshot);
    }
}
