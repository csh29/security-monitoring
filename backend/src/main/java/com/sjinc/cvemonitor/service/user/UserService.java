package com.sjinc.cvemonitor.service.user;

import com.sjinc.cvemonitor.domain.User;
import com.sjinc.cvemonitor.dto.user.UserRequest;
import com.sjinc.cvemonitor.dto.user.UserResponse;
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

    private final UserRepository userRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;
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
                .password(password)
                .role(request.role())
                .build();

        return UserResponse.from(userRepository.save(user));
    }

    /** 사용자 삭제 시, 해당 사용자에게 부여된 프로그램 권한도 함께 정리한다. */
    @Transactional
    public void deleteUser(Long id) {
        userProgramPermissionRepository.deleteAll(userProgramPermissionRepository.findByUserId(id));
        userRepository.deleteById(id);
    }
}
