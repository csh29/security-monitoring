package com.sjinc.securitymonitor.dto.comcd;

/** 공통코드마스터 관리 화면의 "저장" 버튼 클릭 시 전송하는 요청. codeGroup이 이미 존재하면 수정, 아니면 신규 등록. */
public record ComCdGroupRequest(String codeGroup, String groupName, Integer sortOrder, String useYn, String remark) {
}
