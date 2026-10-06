package com.sjinc.securitymonitor.service.user;

import com.sjinc.securitymonitor.domain.User;
import com.sjinc.securitymonitor.dto.user.PasswordChangeRequest;
import com.sjinc.securitymonitor.repository.ComCdRepository;
import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import com.sjinc.securitymonitor.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserServiceTest {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4); // 테스트 속도용 낮은 강도
    private UserService service;
    private User user;

    @BeforeEach
    void setUp() {
        UserRepository userRepository = mock(UserRepository.class);
        service = new UserService(userRepository, mock(UserProgramPermissionRepository.class),
                mock(ComCdRepository.class), passwordEncoder);

        user = User.builder().id(1L).username("tester").userNm("테스터")
                .password(passwordEncoder.encode("old-pw")).role("USER").build();
        when(userRepository.findByUsername("tester")).thenReturn(Optional.of(user));
    }

    @Test
    void 현재_비밀번호가_맞으면_새_비밀번호로_바뀐다() {
        service.changeMyPassword("tester", new PasswordChangeRequest("old-pw", "new-pw"));

        assertThat(passwordEncoder.matches("new-pw", user.getPassword())).isTrue();
    }

    @Test
    void 현재_비밀번호가_틀리면_거부한다() {
        assertThatThrownBy(() -> service.changeMyPassword("tester", new PasswordChangeRequest("wrong", "new-pw")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("현재 비밀번호");
        assertThat(passwordEncoder.matches("old-pw", user.getPassword())).isTrue();
    }

    @Test
    void 새_비밀번호가_비었거나_현재와_같으면_거부한다() {
        assertThatThrownBy(() -> service.changeMyPassword("tester", new PasswordChangeRequest("old-pw", " ")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.changeMyPassword("tester", new PasswordChangeRequest("old-pw", "old-pw")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
