package com.sjinc.cvemonitor.dto.program;

/**
 * 화면의 "저장" 버튼 클릭 시 전송하는 요청. id(program_id)가 이미 존재하면 수정, 아니면 신규 등록.
 * searchYn~resetYn은 공통 버튼 사용 여부("Y"/"N", 비어 있으면 N), etc1Nm~etc5Nm은 기타 버튼 이름(비우면 안 씀).
 */
public record ProgramRequest(String id, String programNm, String url, Integer sortOrder, String useYn,
                             String searchYn, String newYn, String saveYn, String deleteYn, String resetYn,
                             String etc1Nm, String etc2Nm, String etc3Nm, String etc4Nm, String etc5Nm) {
}
