package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.dto.user.PasswordChangeRequest;
import com.sjinc.cvemonitor.dto.user.UserRequest;
import com.sjinc.cvemonitor.dto.user.UserResponse;
import com.sjinc.cvemonitor.security.RequiresProgram;
import com.sjinc.cvemonitor.service.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

/**
 * 사용자 관리 화면(조회/저장/삭제 버튼)과, 사용자별 권한관리 화면의 사용자 select가 호출하는
 * REST API. 목록 조회는 두 화면이 같이 쓰므로 둘 중 하나의 권한만 있어도 되지만, 계정을
 * 추가/수정(비밀번호·역할 변경 포함)/삭제하는 건 "user-mng" 권한이 있어야 한다 —
 * 그렇지 않으면 임의 계정의 비밀번호/역할을 바꿀 수 있는(POST에 id 지정) 심각한 권한 상승
 * 경로가 된다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @GetMapping
    @RequiresProgram({"user-mng", "user-permission-mng"})
    public List<UserResponse> getUsers() {
        return userService.getAllUsers();
    }

    @PostMapping
    @RequiresProgram("user-mng")
    public UserResponse saveUser(@RequestBody UserRequest request) {
        return userService.saveUser(request);
    }

    /**
     * 상단바 "비밀번호 변경" — 로그인한 본인 계정만 바꾼다. 대상을 Principal로 정하므로 다른 계정을 건드릴
     * 수 없고, 모든 사용자가 써야 하는 기능이라 {@code @RequiresProgram}을 걸지 않는다(로그인만 필요).
     */
    @PostMapping("/me/password")
    public void changeMyPassword(@RequestBody PasswordChangeRequest request, Principal principal) {
        userService.changeMyPassword(principal.getName(), request);
    }

    @DeleteMapping("/{id}")
    @RequiresProgram("user-mng")
    public void deleteUser(@PathVariable Long id, Principal principal) {
        userService.deleteUser(id, principal.getName());
    }
}
