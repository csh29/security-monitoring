package com.sjinc.securitymonitor.service.user;

import com.sjinc.securitymonitor.domain.ComCd;
import com.sjinc.securitymonitor.domain.User;
import com.sjinc.securitymonitor.dto.user.PasswordChangeRequest;
import com.sjinc.securitymonitor.dto.user.UserRequest;
import com.sjinc.securitymonitor.dto.user.UserResponse;
import com.sjinc.securitymonitor.repository.ComCdRepository;
import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import com.sjinc.securitymonitor.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserServiceTest {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4); // 테스트 속도용 낮은 강도
    private UserService service;
    private User user;
    private User admin;
    private User other;
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        ComCdRepository comCdRepository = mock(ComCdRepository.class);
        service = new UserService(userRepository, mock(UserProgramPermissionRepository.class),
                comCdRepository, passwordEncoder);

        user = User.builder().id(1L).username("tester").userNm("테스터")
                .password(passwordEncoder.encode("old-pw")).role("USER").build();
        admin = User.builder().id(2L).username("boss").userNm("관리자").password("x").role("ADMIN").build();
        other = User.builder().id(3L).username("peer").userNm("동료").password("x").role("USER").build();
        for (User u : List.of(user, admin, other)) {
            when(userRepository.findByUsername(u.getUsername())).thenReturn(Optional.of(u));
            when(userRepository.findById(u.getId())).thenReturn(Optional.of(u));
        }
        when(userRepository.findAll()).thenReturn(List.of(user, admin, other));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(comCdRepository.findByCodeGroupAndUseYnOrderBySortOrderAsc("ROLE", "Y")).thenReturn(List.of(
                ComCd.builder().codeGroup("ROLE").codeValue("ADMIN").sortOrder(1).build(),
                ComCd.builder().codeGroup("ROLE").codeValue("USER").sortOrder(2).build()));
    }

    @Test
    void 자기_자신은_비밀번호만_바뀐다() {
        service.saveUser(new UserRequest(1L, "renamed", "바꿈", "self-pw", "ADMIN", "N"), "tester");

        assertThat(passwordEncoder.matches("self-pw", user.getPassword())).isTrue();
        assertThat(user.getUsername()).isEqualTo("tester");
        assertThat(user.getRole()).isEqualTo("USER");
        assertThat(user.getUseYn()).isEqualTo("Y");
    }

    @Test
    void 더_높은_역할은_저장_삭제할_수_없다() {
        assertThatThrownBy(() -> service.saveUser(new UserRequest(2L, "boss", "관리자", "", "ADMIN", "Y"), "tester"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.deleteUser(2L, "tester"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 자신보다_높은_역할은_줄_수_없다() {
        assertThatThrownBy(() -> service.saveUser(new UserRequest(3L, "peer", "동료", "", "ADMIN", "Y"), "tester"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("높은 역할");
        assertThatThrownBy(() -> service.saveUser(new UserRequest(null, "new", "신규", "pw", "ADMIN", "Y"), "tester"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 같거나_낮은_역할은_저장되고_목록에_편집가능으로_표시된다() {
        assertThat(service.getAssignableRoles("tester")).containsExactly("USER");
        assertThat(service.getAssignableRoles("boss")).containsExactly("ADMIN", "USER");

        assertThat(service.saveUser(new UserRequest(3L, "peer", "동료", "", "USER", "N"), "tester").useYn()).isEqualTo("N");
        assertThat(service.saveUser(new UserRequest(1L, "tester", "테스터", "", "USER", "Y"), "boss").username()).isEqualTo("tester");

        assertThat(service.getAllUsers("tester")).extracting(UserResponse::username, UserResponse::editable)
                .containsExactly(tuple("tester", false),
                        tuple("boss", false),
                        tuple("peer", true));
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
