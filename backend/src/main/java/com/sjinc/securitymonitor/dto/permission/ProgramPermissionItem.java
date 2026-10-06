package com.sjinc.securitymonitor.dto.permission;

import com.sjinc.securitymonitor.domain.UserProgramPermission;

/**
 * 사용자별 권한관리 화면의 한 행 — 사용자가 그 프로그램에 접근할 수 있고(행이 있으면 접근 권한),
 * 그 화면에서 어떤 공통 버튼을 쓸 수 있는지("Y"/"N", 비어 있으면 N). 조회 응답과 저장 요청에 같이 쓴다.
 */
public record ProgramPermissionItem(String programId,
                                    String searchYn, String newYn, String saveYn, String deleteYn, String resetYn,
                                    String etc1Yn, String etc2Yn, String etc3Yn, String etc4Yn, String etc5Yn) {

    public static ProgramPermissionItem from(UserProgramPermission perm) {
        return new ProgramPermissionItem(perm.getProgram().getProgramId(),
                perm.getSearchYn(), perm.getNewYn(), perm.getSaveYn(), perm.getDeleteYn(), perm.getResetYn(),
                perm.getEtc1Yn(), perm.getEtc2Yn(), perm.getEtc3Yn(), perm.getEtc4Yn(), perm.getEtc5Yn());
    }
}
