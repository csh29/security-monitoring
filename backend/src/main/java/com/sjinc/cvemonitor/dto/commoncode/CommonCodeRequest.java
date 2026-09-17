package com.sjinc.cvemonitor.dto.commoncode;

/** 공통코드관리 화면의 "저장" 버튼 클릭 시 전송하는 요청. id가 있으면 수정, 없으면 신규 등록. */
public record CommonCodeRequest(Long id, String codeGroup, String codeValue, String codeName,
                                 Integer sortOrder, String useYn) {
}
