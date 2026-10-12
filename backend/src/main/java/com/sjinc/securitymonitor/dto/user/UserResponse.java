package com.sjinc.securitymonitor.dto.user;

import com.sjinc.securitymonitor.domain.User;

/**
 * 사용자 관리 화면에 내려주는 응답. 비밀번호(해시)는 절대 포함하지 않는다.
 * editable: 조회한 사람이 이 계정을 저장·삭제할 수 있는지(자기 자신·더 높은 역할이면 false). self: 본인 계정(비밀번호만 변경 가능).
 */
public record UserResponse(Long id, String username, String userNm, String role, String useYn,
                           boolean editable, boolean self) {

    public static UserResponse from(User user) {
        return from(user, false, false);
    }

    public static UserResponse from(User user, boolean editable, boolean self) {
        return new UserResponse(user.getId(), user.getUsername(), user.getUserNm(), user.getRole(), user.getUseYn(),
                editable, self);
    }
}
