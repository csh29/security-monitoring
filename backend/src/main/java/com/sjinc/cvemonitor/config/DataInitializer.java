package com.sjinc.cvemonitor.config;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.domain.CommonCode;
import com.sjinc.cvemonitor.domain.CommonCodeGroup;
import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.domain.User;
import com.sjinc.cvemonitor.domain.UserProgramPermission;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.CommonCodeGroupRepository;
import com.sjinc.cvemonitor.repository.CommonCodeRepository;
import com.sjinc.cvemonitor.repository.ProgramRepository;
import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import com.sjinc.cvemonitor.repository.UserRepository;
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
    private final CommonCodeGroupRepository commonCodeGroupRepository;
    private final CommonCodeRepository commonCodeRepository;
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

        Program commonCodeManagement = programRepository.save(Program.builder()
                .programId("common-code-management")
                .name("공통코드관리")
                .url("/program/common-code-management")
                .sortOrder(5)
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

        userProgramPermissionRepository.save(UserProgramPermission.builder()
                .user(admin)
                .program(commonCodeManagement)
                .build());

        // 화면마다 하드코딩되던 select 옵션(역할/심각도/처리상태)을 공통코드로 관리한다. 마스터(그룹)를
        // 먼저 만들고, 값(codeValue)은 기존 화면 로직/뱃지 클래스가 그대로 참조하던 문자열과 동일하게 디테일을 심는다.
        commonCodeGroupRepository.save(CommonCodeGroup.builder()
                .codeGroup("ROLE").groupName("역할").sortOrder(1).useYn("Y").build());
        commonCodeGroupRepository.save(CommonCodeGroup.builder()
                .codeGroup("SEVERITY").groupName("심각도").sortOrder(2).useYn("Y").build());
        commonCodeGroupRepository.save(CommonCodeGroup.builder()
                .codeGroup("VULN_STATUS").groupName("처리여부").sortOrder(3).useYn("Y").build());

        int sort = 1;
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("ROLE").codeValue("ADMIN").codeName("ADMIN").sortOrder(sort++).useYn("Y").build());
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("ROLE").codeValue("USER").codeName("USER").sortOrder(sort).useYn("Y").build());

        sort = 1;
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("SEVERITY").codeValue("CRITICAL").codeName("CRITICAL").sortOrder(sort++).useYn("Y").build());
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("SEVERITY").codeValue("HIGH").codeName("HIGH").sortOrder(sort++).useYn("Y").build());
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("SEVERITY").codeValue("MEDIUM").codeName("MEDIUM").sortOrder(sort++).useYn("Y").build());
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("SEVERITY").codeValue("LOW").codeName("LOW").sortOrder(sort).useYn("Y").build());

        sort = 1;
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("VULN_STATUS").codeValue("OPEN").codeName("미해결").sortOrder(sort++).useYn("Y").build());
        commonCodeRepository.save(CommonCode.builder()
                .codeGroup("VULN_STATUS").codeValue("RESOLVED").codeName("처리완료").sortOrder(sort).useYn("Y").build());

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
}
