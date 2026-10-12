package com.sjinc.securitymonitor.service.user;

import com.sjinc.securitymonitor.domain.ComCd;
import com.sjinc.securitymonitor.domain.User;
import com.sjinc.securitymonitor.dto.user.PasswordChangeRequest;
import com.sjinc.securitymonitor.dto.user.UserRequest;
import com.sjinc.securitymonitor.dto.user.UserResponse;
import com.sjinc.securitymonitor.repository.ComCdRepository;
import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import com.sjinc.securitymonitor.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
    public List<UserResponse> getAllUsers(String currentUsername) {
        Map<String, Integer> ranks = roleRanks();
        int myRank = currentUserRank(currentUsername, ranks);
        return userRepository.findAll().stream()
                .map(user -> UserResponse.from(user, canManage(user, currentUsername, myRank, ranks),
                        user.getUsername().equals(currentUsername)))
                .toList();
    }

    /**
     * request.id()가 있으면 수정, 없으면 신규 등록. password가 비어있는 수정 요청은 기존 비밀번호를 유지한다.
     * 자기 자신은 비밀번호만 바뀌고, 자신보다 높은 역할의 계정은 저장할 수 없으며, 자신보다 높은 역할을 줄 수도 없다(권한 상승 방지).
     */
    @Transactional
    public UserResponse saveUser(UserRequest request, String currentUsername) {
        if (request.id() != null) {
            User existing = userRepository.findById(request.id())
                    .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + request.id()));
            if (existing.getUsername().equals(currentUsername)) {
                // 나머지 값(역할·사용여부 등)은 보내와도 무시한다.
                if (request.password() != null && !request.password().isBlank()) {
                    existing.changePassword(passwordEncoder.encode(request.password()));
                }
                return UserResponse.from(existing, false, true);
            }
        }

        Map<String, Integer> ranks = roleRanks();
        validateRole(request.role(), ranks);
        int myRank = currentUserRank(currentUsername, ranks);
        if (ranks.get(request.role()) < myRank) {
            throw new IllegalArgumentException("자신보다 높은 역할은 줄 수 없습니다: " + request.role());
        }

        String useYn = "N".equals(request.useYn()) ? "N" : "Y";
        String password;
        if (request.id() != null) {
            User existing = userRepository.findById(request.id())
                    .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + request.id()));
            password = (request.password() == null || request.password().isBlank())
                    ? existing.getPassword()
                    : passwordEncoder.encode(request.password());
            if (!canManage(existing, currentUsername, myRank, ranks)) {
                throw new IllegalArgumentException("자신보다 높은 역할의 사용자는 저장할 수 없습니다: "
                        + existing.getUsername());
            }
        } else {
            password = passwordEncoder.encode(request.password());
        }

        User user = User.builder()
                .id(request.id())
                .username(request.username())
                .userNm(request.userNm())
                .password(password)
                .role(request.role())
                .useYn(useYn)
                .build();

        return UserResponse.from(userRepository.save(user));
    }

    /** 로그인 사용자가 줄 수 있는 역할 코드(자신과 같거나 낮은 등급, 정렬순서대로). 화면 역할 select가 쓴다. */
    @Transactional(readOnly = true)
    public List<String> getAssignableRoles(String currentUsername) {
        Map<String, Integer> ranks = roleRanks();
        int myRank = currentUserRank(currentUsername, ranks);
        return ranks.entrySet().stream()
                .filter(entry -> entry.getValue() >= myRank)
                .map(Map.Entry::getKey)
                .toList();
    }

    /** 상단바의 로그인 사용자 표시. 세션은 살아 있는데 계정이 지워진 경우(다른 관리자가 삭제)는 빈 값. */
    @Transactional(readOnly = true)
    public Optional<UserResponse> getUser(String username) {
        return userRepository.findByUsername(username).map(UserResponse::from);
    }

    /**
     * 로그인한 본인의 비밀번호 변경. 현재 비밀번호를 다시 확인한다 — 세션만 있으면 바꿀 수 있게 두면
     * 자리를 비운 사이 열린 화면이나 탈취된 세션으로 비밀번호까지 바꿔 계정을 통째로 가져갈 수 있다.
     */
    @Transactional
    public void changeMyPassword(String username, PasswordChangeRequest request) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + username));

        if (request.currentPassword() == null
                || !passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("현재 비밀번호가 일치하지 않습니다.");
        }
        if (request.newPassword() == null || request.newPassword().isBlank()) {
            throw new IllegalArgumentException("새 비밀번호를 입력하세요.");
        }
        if (passwordEncoder.matches(request.newPassword(), user.getPassword())) {
            throw new IllegalArgumentException("새 비밀번호가 현재 비밀번호와 같습니다.");
        }

        user.changePassword(passwordEncoder.encode(request.newPassword()));
    }

    /**
     * 역할 값이 공통코드 ROLE 그룹에 있는 값인지 확인한다(화면 select와 같은 출처).
     * 이 값은 {@code User.roles(...)}로 그대로 넘어가 잘못된 값이면 저장은 성공하고 그 계정의 로그인만 나중에 깨진다.
     */
    private void validateRole(String role, Map<String, Integer> ranks) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("역할은 필수입니다.");
        }
        if (!ranks.containsKey(role)) {
            throw new IllegalArgumentException(
                    "허용되지 않은 역할입니다: " + role + " (허용: " + String.join(", ", ranks.keySet()) + ")");
        }
    }

    /** 공통코드 ROLE의 정렬순서가 등급이다(작을수록 높음, 예: ADMIN 1 > USER 2). */
    private Map<String, Integer> roleRanks() {
        Map<String, Integer> ranks = new LinkedHashMap<>();
        for (ComCd code : comCdRepository.findByCodeGroupAndUseYnOrderBySortOrderAsc(ROLE_CODE_GROUP, "Y")) {
            ranks.put(code.getCodeValue(), code.getSortOrder() == null ? Integer.MAX_VALUE : code.getSortOrder());
        }
        return ranks;
    }

    /** 자기 자신이 아니고 역할이 자신과 같거나 낮은 계정만 저장·삭제할 수 있다. */
    private static boolean canManage(User target, String currentUsername, int myRank, Map<String, Integer> ranks) {
        return !target.getUsername().equals(currentUsername) && rankOf(target.getRole(), ranks) >= myRank;
    }

    /** 코드에 없는(사용 중지된) 역할은 가장 낮은 등급으로 본다. */
    private static int rankOf(String role, Map<String, Integer> ranks) {
        return ranks.getOrDefault(role, Integer.MAX_VALUE);
    }

    private int currentUserRank(String currentUsername, Map<String, Integer> ranks) {
        User me = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + currentUsername));
        return rankOf(me.getRole(), ranks);
    }

    /**
     * 사용자 삭제 시, 해당 사용자에게 부여된 프로그램 권한도 함께 정리한다.
     *
     * <p>자기 자신은 지우지 못하게 막는다 — 사용자 관리 권한을 가진 마지막 사람이 자기 계정을
     * 지우면 아무도 사용자/권한을 손댈 수 없는 상태가 되고, 화면으로는 되돌릴 방법이 없다(DB를 직접 고치거나 data 폴더를 지우고 새로 시작해야 한다).
     */
    @Transactional
    public void deleteUser(Long id, String currentUsername) {
        User target = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다: " + id));

        if (target.getUsername().equals(currentUsername)) {
            throw new IllegalArgumentException("자기 자신은 삭제할 수 없습니다.");
        }
        Map<String, Integer> ranks = roleRanks();
        if (!canManage(target, currentUsername, currentUserRank(currentUsername, ranks), ranks)) {
            throw new IllegalArgumentException("자신보다 높은 역할의 사용자는 삭제할 수 없습니다: " + target.getUsername());
        }

        userProgramPermissionRepository.deleteAll(userProgramPermissionRepository.findByUserId(id));
        userRepository.deleteById(id);
    }
}
