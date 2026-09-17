package com.sjinc.cvemonitor.dto.commoncode;

/** 공통코드관리 화면 좌측(그룹) "저장" 버튼 클릭 시 전송하는 요청. codeGroup이 이미 존재하면 수정, 아니면 신규 등록. */
public record CommonCodeGroupRequest(String codeGroup, String groupName, Integer sortOrder, String useYn) {
}
