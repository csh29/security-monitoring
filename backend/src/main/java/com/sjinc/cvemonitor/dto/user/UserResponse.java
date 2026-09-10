package com.sjinc.cvemonitor.dto.user;

import com.sjinc.cvemonitor.domain.User;

/** 사용자 관리 화면에 내려주는 응답. 비밀번호(해시)는 절대 포함하지 않는다. */
public record UserResponse(Long id, String username, String role) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getRole());
    }
}
