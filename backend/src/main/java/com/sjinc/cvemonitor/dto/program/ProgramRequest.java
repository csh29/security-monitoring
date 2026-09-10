package com.sjinc.cvemonitor.dto.program;

/** 화면의 "저장" 버튼 클릭 시 전송하는 요청. id(program_id)가 이미 존재하면 수정, 아니면 신규 등록. */
public record ProgramRequest(String id, String name, String url, Integer sortOrder, String useYn) {
}
