package com.sjinc.cvemonitor.service.user;

import com.sjinc.cvemonitor.domain.ComCd;
import com.sjinc.cvemonitor.domain.User;
import com.sjinc.cvemonitor.dto.user.UserRequest;
import com.sjinc.cvemonitor.dto.user.UserResponse;
import com.sjinc.cvemonitor.repository.ComCdRepository;
import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import com.sjinc.cvemonitor.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 사용자 관리 화면(조회/저장/삭제 버튼)의 처리를 담당한다. */
@Service
@RequiredArgsConstructor
public class UserService {

    /** 역할 값의 출처. 화면 select도 이 그룹을 ComCd.fillSelect로 채운다. */
    private static final String ROLE_CODE_GROUP = "ROLE";

    private final UserRepository userRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;
    private final ComCdRepository comCdRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::from)
                .toList();
    }

    /** request.id()가 있으면 수정, 없으면 신규 등록. password가 비어있는 수정 요청은 기존 비밀번호를 유지한다. */
    @Transactional
    public UserResponse saveUser(UserRequest request) {
        validateRole(request.role());

        String password;
        if (request.id() != null) {
            User existing = userRepository.findById(request.id())
                    .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + request.id()));
            password = (request.password() == null || request.password().isBlank())
                    ? existing.getPassword()
                    : passwordEncoder.encode(request.password());
        } else {
            password = passwordEncoder.encode(request.password());
        }

        User user = User.builder()
                .id(request.id())
                .username(request.username())
                .userNm(request.userNm())
                .password(password)
                .role(request.role())
                .build();

        return UserResponse.from(userRepository.save(user));
    }

    /**
     * 역할 값이 공통코드 ROLE 그룹에 있는 값인지 확인한다.
     *
     * <p>이 값은 {@code CustomUserDetailsService}에서 {@code User.roles(...)}로 그대로 넘어가는데,
     * Spring Security는 여기에 {@code ROLE_} 접두사가 붙어 있으면 예외를 던진다 — 즉 임의 문자열을
     * 그대로 저장해두면 저장은 성공하고 <b>그 계정의 로그인만 나중에 깨진다.</b> 화면 select가
     * 이미 같은 공통코드 그룹으로 채워지므로, 서버도 같은 출처를 기준으로 검증한다.
     */
    private void validateRole(String role) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("역할은 필수입니다.");
        }

        List<String> allowedRoles = comCdRepository
                .findByCodeGroupAndUseYnOrderBySortOrderAsc(ROLE_CODE_GROUP, "Y").stream()
                .map(ComCd::getCodeValue)
                .toList();

        if (!allowedRoles.contains(role)) {
            throw new IllegalArgumentException(
                    "허용되지 않은 역할입니다: " + role + " (허용: " + String.join(", ", allowedRoles) + ")");
        }
    }

    /**
     * 사용자 삭제 시, 해당 사용자에게 부여된 프로그램 권한도 함께 정리한다.
     *
     * <p>자기 자신은 지우지 못하게 막는다 — 사용자 관리 권한을 가진 마지막 사람이 자기 계정을
     * 지우면 아무도 사용자/권한을 손댈 수 없는 상태가 되고, 인메모리 H2라 복구 수단도 재기동밖에 없다.
     */
    @Transactional
    public void deleteUser(Long id, String currentUsername) {
        User target = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + id));

        if (target.getUsername().equals(currentUsername)) {
            throw new IllegalArgumentException("자기 자신은 삭제할 수 없습니다.");
        }

        userProgramPermissionRepository.deleteAll(userProgramPermissionRepository.findByUserId(id));
        userRepository.deleteById(id);
    }
}
